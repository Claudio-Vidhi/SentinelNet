# Changelog

Notable changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/), with `core/version.py` as the single source of
truth.

This file starts at 0.24.0. Earlier releases were not written up as they
happened — `git log --grep="chore(release)"` is the record for those.

## [Unreleased]

## [0.30.1] - 2026-09-05

### Changed

- **I due elenchi di apparati non sono piu' una `<select multiple>`.** Quella
  nativa non prende il tema (righe chiare dentro una console scura), tiene una
  barra di scorrimento dentro la barra dei filtri, non dice quanti apparati
  sono scelti e chiede Ctrl/Cmd per fare la cosa piu' comune della vista — con
  l'istruzione stampata sotto, fuori allineamento da tutto il resto. Al suo
  posto un selettore a caselle dentro un `<details>`, cioe' lo stesso dropdown
  del resto della console: il riepilogo dice "3 di 12 selezionati", l'elenco si
  filtra scrivendo, e "Tutti"/"Nessuno" agiscono su cio' che il filtro sta
  mostrando. Vale per le Tabelle di Routing e per Traffico → Per policy, e le
  funzioni stanno una volta sola in `core.js`.

- **La catena dei salti passa da SVG a HTML.** Il disegno veniva scalato per
  stare in larghezza, quindi con un hostname lungo il nome finiva sopra il
  proprio indirizzo e su un pannello stretto il testo scendeva sotto i dieci
  pixel. Ora ogni riquadro si dimensiona sul suo contenuto — ruolo, nome e IP
  su tre righe — la catena scorre se serve, e sotto i 900px si dispone in
  colonna, che e' come la si guarda da un tablet in piedi davanti al rack. Il
  riquadro d'esito resta l'unico colorato: e' l'unico posto dove il colore
  significa stato.
- **Il motivo della scelta ha una riga sua** invece di stare schiacciato a
  destra dell'intestazione; il richiamo al backup e' un contrassegno accanto al
  nome, e le colonne numeriche della tabella candidate non galleggiano piu' in
  mezzo alla riga. Via anche le frecce di ordinamento: li' l'ordine *e'*
  l'informazione — prefisso, distanza, metrica — e riordinare la tabella la
  renderebbe illeggibile.

### Fixed

- **Il ripiego sul backup poteva leggere il backup di un altro cliente.**
  `analyze_device()` cercava il file per solo suffisso IP in tutto
  `backup-config/`, e due clienti possono avere lo stesso indirizzo — e' la
  premessa su cui e' scritto `assert_device_allowed`, ed e' il motivo per cui i
  backup stanno in cartelle separate per tenant. Un apparato irraggiungibile del
  cliente A restituiva quindi le statiche del cliente B, se la sua copia era
  piu' recente. Ora la ricerca accetta il tenant e cammina solo nel suo albero,
  come fa gia' `remove_stale_backups`; lo passano il ripiego delle rotte e
  `/api/config-analyzer/{ip}`, che il gruppo lo hanno gia' in mano.
- **Sedici salti non sono un anello.** Esaurire il limite senza mai rivedere un
  apparato veniva riportato come "anello", mandando a cercare un giro che non
  c'era: ora e' un esito suo, "limite salti".
- **Indirizzi IPv6 rifiutati davvero.** `/api/routes/trace` diceva di volere
  IPv4 ma accettava un v6, che poi attraversava una pipeline IPv4 e usciva come
  un incomprensibile "nessuna rotta".
- **Stesso IP in due tenant: la traccia si ferma.** Le tabelle si indicizzano
  per indirizzo, quindi una selezione ambigua non avrebbe dato un percorso
  sbagliato a meta' ma uno che mescola due reti senza dirlo. Ora e' un 409 che
  nomina i tenant.
- **Interfacce FortiOS lette anche come `ipv4_address`**, il nome che alcune
  build usano — `fortigate_service` lo faceva gia'. Senza, l'apparato tornava
  zero indirizzi in silenzio e ogni suo next-hop diventava "fuori inventario".
- **Distanza e metrica accettate anche come stringhe numeriche**: scartare
  `"110"` come se fosse assente faceva sembrare identiche due rotte diverse, e
  nasceva una biforcazione ECMP inventata.
- **L'ultimo tratto della striscia si accende.** L'animazione cercava il
  riquadro successivo per indice, e il riquadro d'esito non ne aveva uno: su un
  percorso di un salto solo — l'unico tratto esistente — la linea e la sua
  etichetta non comparivano mai.
- **Contrasto in tema chiaro.** Il pannello usava i colori delle lampade come
  inchiostro (`--success` come testo su fondo bianco sta sotto 4.5:1) e la
  sigla del tipo di rotta prendeva `var(--bg)`, cioe' testo quasi bianco su
  ambra. Ora usa gli inchiostri dedicati (`--lamp-*-ink`).

## [0.30.0] - 2026-09-05

### Added

- **Analisi di percorso: dove finisce un indirizzo, e perché quella rotta.**
  Le tabelle raccolte rispondono anche alla domanda successiva —
  `GET /api/routes/trace?device=<selezione>&src=<apparato>&dst=<indirizzo>`
  ricostruisce i salti fra gli apparati **scelti** e, per ognuno, le rotte
  candidate, quella che vince e il criterio che ha deciso (prefisso, distanza
  amministrativa, metrica). Gli esiti restano distinti perché sono domande
  diverse: consegna, fuori inventario, nessuna rotta, anello, biforcazione
  ECMP, e "non interrogato" quando il percorso esce dalla selezione.

  Per concatenare due salti serviva un dato che le rotte da sole non danno:
  **l'indirizzo delle interfacce**, senza cui non si sa quale apparato possieda
  un certo next-hop. Viene preso dove già esiste — `monitor/system/interface`
  per i FortiGate, le rotte *local* (`L 10.0.0.1/32`) del `show ip route` per
  gli switch — quindi nessun collector nuovo. Un next-hop viene attribuito solo
  a chi ha quell'indirizzo esatto: per vicinanza di sottorete sarebbe topologia
  inventata.

- **Il pannello nel tab Rotte.** Sopra il grafico: si sceglie l'apparato di
  partenza fra quelli selezionati, si scrive un indirizzo e la striscia disegna
  i salti, uno alla volta, mentre sotto compaiono le decisioni — le rotte
  candidate di ogni apparato, quella che vince e il criterio che ha deciso, con
  i criteri successivi barrati perche' non vengono nemmeno guardati. Un salto
  letto dal backup resta marcato dentro la catena. L'animazione e' la
  spiegazione, non un effetto: `prefers-reduced-motion` mostra tutto subito, e
  "Riproduci" la ripete quando serve.

  Il pulsante della prova sul campo compare solo per operatori e admin: a un
  viewer un'azione che manda pacchetti non viene nemmeno offerta.

- **Prova sul campo, opzionale.** `POST /api/routes/trace/probe` lancia un
  traceroute vero **dall'apparato** e confronta i salti visti con quelli
  attesi. È l'unica parte della vista che manda pacchetti: endpoint separato,
  riservato agli operatori, mai innescato dall'apertura di un pannello, con la
  destinazione validata come indirizzo prima di finire in un comando su un
  apparato di rete. Un next-hop atteso che non compare non è di per sé un
  guasto — un apparato può non rispondere a ICMP — ed è presentato come punto
  da guardare, non come verdetto.


- **Routing tables fall back to the backup when a device does not answer.** An
  unreachable device used to leave a line in the errors box and nothing else,
  which is usually the moment its routes are wanted. The freshest configuration
  backup already on disk is read instead — through the same analyzer the Config
  Analysis tab uses, not a second parser beside it.

  What comes out is the **configured static routes**, and the view says so
  rather than passing them off as a routing table: nothing learned (OSPF, BGP,
  RIP), nothing connected, and no way to tell whether a static was actually
  active — its next-hop may have been unreachable for a month. Each such device
  is badged "dal backup" in the table and named in the errors box with the
  backup's date, next to the reason the device was not reached, which is not
  dropped. Routes belonging to a VRF are left out: there is no column in which
  to say which VRF they are from, so beside the others they would read as
  global-table routes.

### Changed

- **Routing tables and "By policy" ask before they query.** Both views used to
  fan out over every device in scope the moment they were opened, and then
  built their device dropdown out of whatever answered. Two consequences: a
  tab opened by accident meant one REST/SSH session per managed device, and a
  device that had never been queried could not be picked — which is why the
  switches were missing from the routing filter even after they learned to
  answer `show ip route`.

  The selectable devices now come from the inventory (`GET /api/routes/devices`,
  `GET /api/firewall-traffic/devices` — inventory reads, no session opened),
  the picker is a multi-select, and the query runs only on Aggiorna / Interroga.
  With nothing selected the API queries nothing and the table says what to do
  instead of showing an empty result that reads like "no routes".

### Added

- **A "By policy" view completes the Traffico tab.** Byte, sessioni e hit per
  policy firewall, aggregate across the firewalls in scope, sorted heaviest
  first — the order in which a traffic table is actually read. Filters by
  firewall, action and a free search over policy name, address objects,
  resolved networks and service; totals beside the filters are computed after
  them, so the summary matches the rows below it.

  These numbers do **not** come from `flow_aggregates` like the rest of the
  tab: they are counters the FortiGate keeps for itself, cumulative since the
  last reset. The tab's time window does not filter them, and the pane says so
  in a banner — 850 MB read under an "Ultime 6 ore" selector otherwise reads as
  850 MB in six hours, wrong by an order of magnitude. "Never hit" is shown as
  its own badge rather than a zero, because a policy with no counter is not a
  dead rule; and a firewall that returns its configuration without its
  counters is reported as a partial answer instead of a table of zeros.


- **Switches reach the Routing Tables tab: `show ip route` is parsed.** The tab
  shipped with FortiGates only, because they are the one vendor that publishes
  a routing table over REST. A switch publishes its RIB too, just as text, and
  the letters in the first column are the classification the device already
  makes of its own table — reading them is translating, not guessing.

  Connected (C) and local (L) stay apart, so a switch does not appear to have
  every SVI twice. A qualifier does not change the family: `O IA` is OSPF like
  `O`. A route with two next-hops becomes two rows, because keeping one hides
  half the path from the person looking for where traffic goes. An age
  (`1d02h`) is not mistaken for an interface. Cisco only: the parser is written
  on the IOS layout, and Aruba answers the same command differently — adding it
  means writing its parser, not widening a list.

  A device in an agent site is not dialled at all — the central has no route to
  it and trying only adds a timeout per refresh — and a switch that answers
  with no routes says so, so the absence does not read as a broken parser.

### Fixed

- **Client diagnosis: the `sessions` section failed on both paths at once.**
  REST asked `monitor/firewall/session`, which answers 404 on FortiOS 7.6.7 —
  the body says `path=firewall name=session action=""`, i.e. the path exists
  but no GET action matches it. The session list lives at
  `monitor/firewall/session/select`, which takes exactly the
  srcaddr/dstaddr/dstport/count this code already sent; the old path stays as a
  second attempt for the versions that served it.

  The SSH fallback then failed too, for an unrelated reason: `ssh_command`
  handed netmiko three `diagnose sys session ...` commands joined by newlines.
  `send_command` waits for the prompt that follows *the* command it is given,
  so it waited for one containing all three lines, never saw it, and reported
  "Pattern not detected" with the whole block quoted back as the pattern. It
  sends one line at a time now, which fixes the same latent break in
  `delete_sessions` and in the config pull.

- **"By IP" said "no traffic" without saying why.** The banner that explains it
  (observability off, no listener, no exporter) lives in the Panoramica pane,
  so it is invisible from that pill. The empty state now carries the diagnosis
  itself, including the distinction people actually trip on: the FortiGate
  traffic logs arrive over REST and do not feed this view, which is fed by
  NetFlow/IPFIX/sFlow reaching the collector.


- **BGP routes were drawn in the fallback grey.** The route-type palette asked
  for `--accent`, which this theme does not define (the tokens are
  `--primary` / `--success` / `--warning` / `--danger` / `--info`): the bar fell
  back to grey and the badge got an invalid `var()`. BGP is `--info` now.


- **A Routing Tables tab: every device's RIB in one view.** The FortiGate tab
  has shown one firewall's routes since it shipped; the question engineers
  actually ask is the other one — "who has a route to this network, and do the
  two devices agree" — and answering it meant opening that tab once per device
  and comparing by eye. Rows are grouped by device and route type, filterable
  by device, type and a free search over network, next-hop and interface, with
  a stacked bar chart above.

  Nothing new is collected: `/api/routes` calls the same
  `fortigate_service.get_routes` across the devices in the caller's scope. Two
  consequences are stated in the UI rather than papered over. Devices that
  only answer over SSH return CLI text, and they are listed as such instead of
  being parsed — a routing-table parser is a collector, and this is not one.
  And the bars count **routes**, not packets: no device exposes per-route
  counters, so a traffic bar there would be an invented number, and the note
  under the chart says so. A device that does not answer appears as a warning
  beside the others, because a missing table otherwise reads as "it has no
  routes".


- **Policy Lookup answers the question it was asked.** "Which policy would
  match this flow" came back as a flat key/value table, with the verdict and
  the policy number two rows among many. It now opens with a banner —
  ALLOWED, DENIED, POLICY MATCHED or NO MATCH — the flow it refers to
  (source, destination, port, protocol, ingress interface, and whether that
  interface was derived from the route), and the firewall's full answer
  underneath in a `<details>`, unchanged. FortiOS returns `policy_id` and
  `success` but not the action: that is read from the policy list the Policy
  pill already downloads, and when it has not been opened the view says where
  to find the action instead of guessing a colour.


- **`tests/test_python_floor.py` parses every tracked module at the declared
  floor.** Development runs on 3.14 and the Docker image builds on 3.11, and
  nothing enforced the gap: syntax the floor rejects passed every local check
  and only failed at `docker build`, or on an agent's first start. The floor
  is read from `pyproject.toml`, so raising it moves the guard with it.

- **`tests/routes.py` walks the route tree instead of iterating `app.routes`
  flat.** The eight suites that assert which routes exist, and with which
  dependencies, would have gone *silently green* on fastapi 0.141+, which
  mounts included routers one level down instead of copying them up. They now
  hold on both sides of the `fastapi<0.141` pin, so lifting it is one line.

- `httpx2` declared next to `httpx` in the dev group: starlette 1.x asks for
  it and warns on every test run when it finds only `httpx`.

### Changed

- **Restart, self-update and certificate generation left the settings
  router.** `routers/settings.py` ran `git pull`, `pip install`, the
  systemd/Windows restart and an 80-line X.509 build between an auth
  dependency and a response dict. That work now lives in
  `services/self_update.py` and `services/cert_manager.py`, and the router is
  490 lines instead of 692. Same routes, same status codes, same audit lines.

- **The inventory is parsed once per version of the file, not once per
  call.** `get_all_devices()` has 64 callers, several inside loops and one on
  every device-scoped route, and each of them re-read and re-parsed
  `network_hosts.csv`. Rows are now kept against the file's `(mtime, size)` —
  so a write from anywhere, the site agent or a spreadsheet, invalidates them
  without anyone remembering to — and handed out as fresh dicts, because
  callers modify what they get. A file written in the last 1.1 s is always
  re-read: ext3 and FAT stamp mtime to the whole second, and two same-size
  writes inside one tick would otherwise pin the cache forever. Measured
  1.4x faster at 200 devices, 4.6x at 1000.

### Fixed

- **A row in the Triage Flow Log did nothing when clicked.** The row carried
  `cursor:pointer` and the detail drawer never opened: the selected id came
  from `row.dataset.id`, which the DOM always returns as a string, and was
  compared with `===` against `e.id`, an INTEGER from `syslog_events`. The
  comparison is on strings now.


- **The 5k pps loop-latency test failed roughly one full run in three.** It
  asserted an absolute p99 under 50 ms, but that number measures the machine's
  scheduling floor, and under `pytest -n 4` the other three workers push it
  past the threshold with the ingest stopped — a red that said nothing about
  the code. It now measures a zero-traffic baseline on the same loop and
  asserts the delta, which is the property it was always about.

- **`test_access_position` left `mac_history.DB_PATH` pointing outside the
  suite directory.** It reassigned the module global in `setUp` and never put
  it back, so `test_shared_paths_are_pinned` failed whenever xdist handed it
  that worker second — about one full run in three, never in isolation. It now
  restores it in `tearDown`, the way `test_arp_collector` already did.

- **`test_gli_ip_arrivano_dall_arp_dello_stesso_tenant` used two clocks for
  one scan.** Two ARP rows inserted either side of a second boundary get
  different `last_seen`, and "most recent per source wins" then discards a
  legitimate binding. Both rows now share one timestamp, like the two
  neighbouring tests that had already been fixed this way.

- **The lazy-tab frontend contract test took 80 seconds.** It compiled a
  lookbehind regex per candidate name and rescanned all 30k lines of JS with
  it, 14,368 times over. One pass per file instead: 0.5 s, same assertions.
  Full suite under `-n 4`: 152 s before, 55-107 s after over four
  consecutive runs, all green.

- **The release script printed commands that PowerShell could not run.** It
  used a bash line-continuation backslash, which PowerShell passes through as
  an extra argument: `gh` read it as an asset file to upload, and publishing
  0.28.0 failed halfway (twice) before `gh` rolled the releases back. The
  commands are now one per line, and a test reads the printed block back and
  fails if a line ever ends in a backslash again.

## [0.28.0] - 2026-09-02

### Added

- **The central can update itself.** The agent has been able to since 0.27.1;
  the central still needed the manual SSH sequence — `git pull`,
  `pip install`, `systemctl restart` — which is the shell the Settings tab
  exists to avoid. An *Aggiorna e riavvia* button now runs those three in
  order, and stops at the first one that fails. A failed dependency install
  cancels the restart, so the previous version keeps serving; a pull that
  changed nothing neither installs nor restarts. It refuses on an installation
  with no git repository (an exe), and when nothing supervises the process —
  downloading code that cannot be applied only produces a tree ahead of the
  process running it. Every argv is fixed: there is no parameter for the
  remote, the branch or the repository.

## [0.27.1] - 2026-09-02

### Fixed

- **An agent update left the old code running.** `git pull` writes the new
  files but the process keeps the old modules in memory, so the fleet panel
  went on reporting the previous version until someone ran
  `systemctl restart sentinelnet-agent` by hand on the site host — the very
  shell the button exists to avoid. A self-update that actually changed
  something now installs `requirements.txt` and then restarts the agent itself,
  deferred so the job result reaches the central first. The order matters: an
  update that adds a dependency, restarted without installing it, would
  crash-loop under systemd and leave the site with no agent at all — so a
  failed install cancels the restart and leaves the working old code running.
  A pull that changed nothing, or failed, neither installs nor restarts.

- **The dashboard served stale JavaScript for five minutes after an update.**
  App assets carried `Cache-Control: public, max-age=300`, so the browser used
  its cached copy without even asking, and the only cure was the user knowing
  to press Ctrl+F5. They are now sent with `no-cache`: the browser revalidates
  every load and gets an empty 304 while the file is unchanged. The dashboard
  page itself gets the same treatment, since revalidating the scripts while
  serving a cached page that lists them fixes nothing. Vendor code and fonts
  keep their one-year immutable cache.

## [0.27.0] - 2026-09-02

### Added

- **You could not tell what any part of the fleet was running without SSH.**
  The agent's heartbeat reported a hardcoded `2.6.0` — a string matching
  nothing in the tree — which the central then discarded, so "did my update
  reach that site?" had no answer from the dashboard. The agent now sends its
  real version plus the commit, branch and whether the checkout is dirty, and
  a **Versioni della flotta** panel in Settings lists the central and every
  agent site side by side, marking any agent whose version differs or whose
  checkout is modified.

- **Reading an agent's log meant opening a shell on the site.** A *Leggi log
  agente* button in the agent panel enqueues an RPC that returns the last 200
  journal lines, capped because that string is rendered verbatim in the job
  history where a whole journal is unusable.

- **Settings that need a restart could be changed but not applied.** A restart
  button in Settings starts a separate oneshot systemd unit
  (`sentinelnet-restart.service`, shipped in `docs/deploy/`) which restarts the
  service — the application never exits on its own, so a failed restart leaves
  the old process serving the panel. The endpoint runs one fixed argv with
  nothing from the request body in it, and refuses with 409 when no supervisor
  would bring the process back. On Windows it drives the service instead, when
  the installer declares `SENTINELNET_WINDOWS_SERVICE=1`.

- **A self-signed certificate for this host**, generated from Settings with the
  address in the `subjectAltName` — without which modern clients reject the
  certificate whatever its CN. Built with `cryptography` rather than the
  `openssl` binary, so it behaves the same on Linux, Windows and macOS, and the
  private key is written with restricted permissions on all three. It refuses
  to overwrite an existing certificate, because doing so would drop every agent
  that verifies it, with no undo.

### Changed

- **`Dev` and `master` now carry the same tree.** The publication strip that
  hid `tests/`, `AGENTS.md` and the design documents from the public branch is
  gone, along with `scripts/dev/port_to_master.py`: publishing is
  `git push origin Dev:master`. The strip also meant the test gate could not
  run on the public branch. Since every tracked file is now published, the
  privacy boundary is `git add`, and it has a guard:
  `scripts/check_no_private_data.py` scans the tracked tree for public IP
  addresses, tracked state files and pasted secrets, and runs inside the suite.

- **The site agent is documented as Linux-only**, and a Windows agent is
  explicitly not planned: its remote management is built on systemd and
  `journalctl`. The NSSM instructions that produced an unmanageable Windows
  agent have been removed. Central itself runs on Linux, Windows or Docker.

## [0.26.0] - 2026-09-01

### Added

- **The central can own an agent site's inventory.** A per-site switch,
  *Inventario dal centrale*, makes the central the source of truth for that
  site's device list and hands it to the agent on the heartbeat it already
  makes — so a device added on the central shows up at the site instead of
  having to be typed into a CSV there. Off by default, because switching it on
  means the device credentials live on the central as well as at the site.
  Secrets are withheld unless the agent's connection is TLS: over plain HTTP
  the device identity still travels and the passwords do not. The push adds and
  updates but never deletes, so the agent keeps devices the central has never
  seen.

- **MAC/ARP collection has its own interval.** It is the only phase of the
  agent cycle that opens an SSH session to every device, and it used to run
  once per poll: at a 10 second polling interval that was six sessions a
  minute per switch, for tables that do not change in ten seconds. The new
  `l2_interval` defaults to 300s and is settable from the agent panel; 0 keeps
  the old every-cycle behaviour.

### Added

- **An agent site's devices used to go quiet between deploy and the next
  manual check-in**: the agent mirrored inventory and MAC/ARP tables, but
  nothing told central whether a device was actually up, whether its config
  had drifted, or let an operator ask for a fresh diagnosis without waiting
  for the next scheduled pass. The agent now pushes ping-based status every
  cycle, and backs up each device's config and version on its own
  `backup_interval` (3600 seconds by default, configurable per site from the
  dashboard's agent panel, `0` to disable). An operator can also enqueue a
  `triage` job for an agent-site device the same way they already send a CLI
  command, and get an answer on the agent's next poll — all without central
  ever dialling into the site.

### Security

- **The web terminal's one-time token travelled in the WebSocket URL**, so
  every session wrote it verbatim into the uvicorn access log, journald, any
  reverse-proxy log and the browser history. The token is single-use and
  expires in 30 seconds, so what was logged was already spent — but a secret
  in a URL stops being harmless the moment the lifetime or the single-use
  property changes. The client now sends it as the first WebSocket frame,
  which is logged nowhere, and the endpoint drops a connection that does not
  produce one within 10 seconds.

### Fixed

- **Central dialled the devices of an agent site, which is the one thing the
  mode exists to avoid.** The agent mirrors its inventory into central so the
  dashboard can show it, and every central-side prober then treated those rows
  as its own devices: ICMP from the ping check and the ping monitor, a TCP/22
  reachability test, and SSH sessions for triage and bulk commands. The only
  site gate, `has_direct_path()`, exempted `jump` sites alone. On a routed lab
  this shows up as denied ICMP and denied SSH from central in the customer's
  firewall log; on a NAT'd site it is a device reported permanently "offline"
  because the probe cannot arrive at all. An agent site is now excluded from
  every direct probe and reports the same "not measurable" tri-state a jump
  site does, with a second predicate, `is_agent_site()`, for the operations
  that belong to the agent rather than merely to the network path. A site id
  central does not know keeps its direct path, which is what lets the agent
  run the same code over its own inventory.

- **An agent's polling interval reverted to 60s at every restart.** `--interval`
  carried an argparse default of 60 while being applied with `if args.interval`
  — a test of "did the operator pass this flag?" that was true on every start.
  So an interval changed from the dashboard was persisted into `agent.json`
  correctly and then overwritten by a flag nobody had typed. The default now
  comes from the same `setdefault` as every other one.

- **A device was classified from its hostname while its model sat unused three
  lines away.** The map computed the model out of the device's own backup for
  the table column only, so an inventoried switch with no CDP neighbour to
  describe it was typed from whatever token its name happened to contain — a
  2960X access switch could land in the map as an access point. The model is
  now the first signal the classifier reads, matched against Cisco's product
  families: 91xx is an access point, 92xx-96xx a switch, 9800 a controller,
  Catalyst 8000 a router, Firepower 9300 a firewall and Nexus 9800 a switch,
  none of which the shared "Catalyst"/"c9" prefixes could tell apart.

## [0.25.0] - 2026-08-31

### Fixed

- **FortiGate Policy Lookup always failed, on every device, with "Not
  available on this device".** The query was built with the CLI's parameter
  names instead of the API's: the source address went out as `srcip` where
  FortiOS expects `sourceip`, the protocol as a name where it expects the IP
  protocol number, and the mandatory ingress interface was omitted entirely.
  FortiOS answered 4xx and the generic error renderer turned that into a
  sentence about the device's capabilities — so the failure read as "your
  firewall does not support this" no matter how privileged the API user was.
  The query builder is now shared with the agent-relay path, which carried the
  identical defect where nobody could see it, and a lookup without an explicit
  interface derives one from the route to the source instead of failing.

- **No incident was raised for a port that dropped to `lowerLayerDown` or
  `notPresent`.** The rule matched only `down`/`0`/`false`, so a failed lower
  layer or a pulled transceiver produced no symptom, no evidence and no
  incident — the estate stayed quiet about a port that was genuinely gone. The
  link vocabulary now lives in one place, shared by the rule that raises the
  incident and the view that counts the ports, so the two cannot drift.

- **Interfaces & Expected State: ports that were not up were shown, and
  counted, as operational.** Only `down`/`0`/`false` were treated as down and
  everything else fell through to UP, so a port whose transceiver had been
  pulled (`notPresent`) or whose lower layer had failed (`lowerLayerDown`) read
  as operational on the one view whose job is saying what broke. There is now
  an explicit third state — neither up nor broken — with its own card, filter
  and badge, and only `up` counts as up.
- The same tab silently capped its list at 500 interfaces while presenting
  "Total Ports" as the truth. The response says when it is capped and the tab
  shows it. Twenty 48-port switches were already past it.
- The interface state machine existed twice, in Python and in JavaScript, with
  two different vocabularies. It is computed once, server side, and travels
  with each row.
- Declaring expected state for many ports rewrote the whole settings blob once
  per port, so a concurrent operator's save was lost to whoever finished last.
  One read, one write, whatever the batch size.
- The tab told a new user their *filter* was wrong when nothing had been
  collected at all, and the active filter card had no styling, so clicking one
  confirmed nothing.

### Added

- **Firewall policies now show their source and destination as addresses, not
  just as object names.** `LAN_Uffici` or `port2 address` said nothing about
  which network a rule actually catches, and answering that meant opening the
  address book in another tab and expanding groups by hand. Subnets, ranges,
  groups and the implicit `<interface> address` objects — which are not in the
  address book at all, being derived from the interface's live IP — are
  resolved once and shown in two new columns. FQDN and geography objects
  deliberately show nothing: they have no address until resolved, and printing
  a placeholder there would be inventing one.

### Changed

- **Policy & Route Validation no longer lists firewalls.** Its offline trace
  reads a stored backup, so it cannot resolve an interface-derived address
  object or a dynamically learned route and lands on UNKNOWN — while the same
  question is answered authoritatively by the box itself in FortiGate
  Management. Two answers to one question, one of them structurally worse, is
  how an operator ends up trusting the wrong one. The dropdown says how many
  devices it left out and where to trace them, because a device silently
  missing from a list reads as a broken inventory.

### Security

- `users.json` (every password hash) and `sites.json` (every agent site-token
  hash) had no permission tightening at all — not on the temp copy, not on the
  final file — so on a shared data directory they were readable by whoever the
  directory allowed. Both are now restricted, temp copy first.

- A user restricted to some sites could download another customer's device
  backup. `GET /api/download-backup/{name}` checked the caller's scope against
  the FIRST IP in the requested name but resolved the file from the LAST one,
  so `192.0.2.10-198.51.100.7.txt` passed the check on a device the caller owns
  and returned the backup of one they do not. Every IP in the name is now
  checked. The path-traversal guard was already correct and now has a test.
- The audit report PDF is rendered from client-supplied HTML by a real browser
  running on the server, which would fetch any subresource that HTML named —
  an authenticated request forgery reading internal services from the
  appliance's network position, with the answer painted into the returned PDF.
  The browser is now started with name resolution refused outright (literal IP
  addresses included).
- The Content-Security-Policy gains `base-uri 'none'` and `form-action 'self'`.
  Without `base-uri`, an injected `<base href>` repoints every relative script
  URL and walks around `script-src 'self'`.
- The encryption key file is no longer briefly readable by anyone the data
  directory allows: permissions are tightened on the temporary file before it
  is renamed into place, not only afterwards.
- New guard test: every API route that takes a device IP must reach
  `assert_device_allowed`, directly or through a helper. The deliberate
  exceptions are listed one by one with the reason, so adding an unguarded
  route now fails the suite.


### Fixed

- The NetSec Audit and Policy & Routing Validation tabs no longer carry a
  `preview` badge: both evaluate stored configuration offline, both are among
  the best-covered surfaces in the tree, and neither was waiting on anything. A
  preview tag that outlives its reason teaches people to ignore the ones that
  still mean something. Incidents, Sites and Client Diagnosis keep theirs —
  those are waiting on evidence from the field.
- The Client Diagnosis heading rendered its preview badge twice.

### Removed

- **The MCP Client preview tab is gone.** SentinelNet acting as a client
  *towards* external MCP servers never left preview, and it was hidden behind a
  settings toggle rather than shown with a badge — so it got no real use, and
  real use is what would have validated it. Router, frontend module, external
  client, tab, sub-tab, settings toggle and its i18n keys are deleted outright,
  not left as a flag. The MCP **server** — SentinelNet exposed to Claude
  Desktop and other LLM clients — is untouched.

### Changed

- **Interfaces & Expected State reads as a monitoring console.** Filters for
  tenant and device, the seven state cards became one continuous bank of real
  buttons that reach the keyboard and say which one is engaged, and the second
  row of chips that duplicated them is gone. The table is dense and aligned:
  addresses and counts in the data face, a header that stays put while the list
  scrolls, and the per-row date and note editors appear on the row being
  declared instead of on all of them. The view says how old its data is, and how
  many ports the current filters are showing.

- The Interfaces tab's six port-state cards, the verdict cards on Home and two
  modals now draw from the design system instead of inline styles: type-ramp
  sizes, lamp-wash tints, and the 1px state accent the system specifies rather
  than a 4px slab. The clickable KPI in MAC Tracker has a cue that reads as one.
- `DESIGN.md` documents the 8px plate radius the app actually ships and no
  longer claims modal titles use the 21px Plate Title step; both had drifted
  from the code.
- `docs/hardening.md` states the accepted risk behind FortiGate REST TLS
  verification defaulting to off, and what to do about it.

- The web interface now follows the browser's language on a first visit
  instead of always starting in Italian. An explicit choice from the language
  selector is still remembered and still wins.
- Startup messages no longer come out garbled on a Windows console using a
  legacy code page: `stdout`/`stderr` are reconfigured to UTF-8.
- The "latest snapshot per kind" query behind the observability API context
  now filters by tenant in the inner query too. When two customers each had a
  device on the same IP, a restricted user saw an empty panel instead of their
  own snapshot.

### Fixed

- `README.md` and `docs/development.md` claimed Python 3.14+; the supported
  floor is 3.11, which is what the Docker image and the pinned
  `requirements.txt` actually build against.
- `SECURITY.md` listed supported versions as 0.1.x/0.2.x, several minors
  behind the actual release line.

### Added

- Issue and pull-request templates under `.github/`, routing vulnerability
  reports to a private advisory rather than a public issue.
- `CHANGELOG.md`, this file.

## [0.24.0]

### Added

- Dedicated **Interfaces & Expected State** monitoring tab, with batch
  endpoints behind it.
- Client-side internationalization across the dashboard: every user-facing
  string resolves through the `it`/`en` dictionaries in `static/js/i18n.js`,
  including the correlation-rule catalogue, which `GET /api/incidents/rules`
  now serves in the requested language via an optional `lang` parameter.

### Fixed

- Key files written with Windows DPAPI could not be loaded on non-Windows
  hosts: the Linux/Docker fallback path is now handled instead of raising.
- Correlation rules hardened, and a hardcoded label that bypassed i18n
  corrected.
- Docker image build no longer stalls on an interactive apt prompt
  (`apt-get install -y`).

### Changed

- `data/` and `*.posix` are ignored wholesale, so no runtime state — device
  credentials, databases, backups, keys — can be committed by accident.

## [0.23.0]

### Changed

- Cloud backup enforces the pinned SSH host key after connecting, not only
  before.
- Dead code removed: orphaned functions with no callers, the two unused
  provisioner download endpoints, the per-vendor config-analyzer renderers,
  and the unreachable half of the ARP cluster.
