# Changelog

Notable changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/), with `core/version.py` as the single source of
truth.

This file starts at 0.24.0. Earlier releases were not written up as they
happened — `git log --grep="chore(release)"` is the record for those.

## [Unreleased]

### Added

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
