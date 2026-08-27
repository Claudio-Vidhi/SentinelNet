# Console Rethink — UX/IA Implementation Plan

> **Status**: plan only — no code changed on this branch.
> Branch: `feat/console-rethink`, cut from `Dev` on 2026-08-26.
> Companion analysis: `docs/ui_tab_overlap_analysis.md` (the inventory this plan acts on).
> Design authority: `DESIGN.md`. Product context: `PRODUCT.md`.

Outcome of a four-step UX advisory session: navigation model, high-frequency
workflows, screen real estate, polish. Every claim below was checked against the
tree; four working assumptions were corrected by the code and are marked
**[corrected]** where they changed a recommendation.

---

## Diagnosis

The nav organises by **verb** (Indaga / Inventario / Valuta / Modifica /
Amministra). Users think in **objects** — confirmed in session: tenant first,
then device. That split is correct, but only if the object has somewhere to
live. Today it does not, so every panel re-asks: `ui_tab_overlap_analysis.md`
counts **11 separate tenant selectors**.

Four structural defects follow from it:

1. **Scope is a destination, not a state.** `Siti` and `Gruppi` sit under
   *Amministra* beside `Utenti`. A tenant is something you go and edit, never
   something you stand inside. Group scope is an authorization boundary
   (`user_group_scope`); a boundary the user cannot see is one they cannot trust.
2. **Home is filed as a peer of Incidenti**, inside a verb group. It is the
   surface that decides *whether* you investigate, not an investigation tool.
   Filing it as one of 23 equals is why the sidebar cannot express priority.
3. **Vendor consoles are top-level estate categories.** `FortiGate`, `WLC` and
   `Alta Affidabilità` are facets of a selected device, not categories of the
   estate. A customer with no Fortinet carries the tab forever.
4. **No cross-cutting entry.** 20+ destinations, zero keyboard reach.

### [corrected] The nav is not flat

It already carries five verb groups. Generic "group your tabs" advice does not
apply; the grouping is sound and stays.

### [corrected] `Siti` and `Gruppi` are orthogonal, not duplicates

| | Site (`services/site_manager.py`) | Group (`routers/deps.py:91`) |
| :--- | :--- | :--- |
| Concept | Reachability — how the central reaches devices | Tenancy — who may see what |
| Values | `central` / `agent` / `jump` | free-form tenant string on the device |
| Carries | token hash, agent job queue, jump host | `user_group_scope` set (authz) |
| Persisted | `sites.json` + `agent_jobs.db` | user record |

A customer can span three sites; one site can host two customers. Merging them
would collapse a security boundary into a transport detail. **Rename instead** —
and note `routers/deps.py:104` currently raises `"Site '{group}' is not allowed
for your profile."`, saying *Site* while checking a *Group*.

---

## Target model — object in chrome, verb in the sidebar

```
┌──────────────────────────────────────────────────────────────────────┐
│ SentinelNet   [ Tenant: Customer B · 4 sedi ]     ⌘K   ● 3    utente │  persistent
├──────────────┬───────────────────────────────────────────────────────┤
│ ◆ Situazione │                                                       │  landing, above
│              │                                                       │  the groups
│ INDAGA       │                                                       │
│   Incidenti  │        every panel below inherits Tenant              │
│   Traffico   │                                                       │
│   Endpoint   │                                                       │
│   AI         │                                                       │
│              │                                                       │
│ INVENTARIO   │                                                       │
│   Dispositivi│  device detail hosts FortiGate / WLC / HA as facets    │
│   Topologia  │                                                       │
│   Categorie  │                                                       │
│              │                                                       │
│ VALUTA / MODIFICA / AMMINISTRA                                       │
└──────────────┴───────────────────────────────────────────────────────┘
```

Plus a **device context chip** beside the tenant selector, holding the selected
object across tab switches so the verbs act as lenses on it:

```
[ Tenant: Customer B ]   [ switch-01 · 192.0.2.10  x ]
```

---

## Work items

Sequenced by leverage per unit of effort. Items 1, 3, 5, 6 and 10 are small and
mutually independent — a shippable first pass.

**Items 9 and 11 come first regardless of that ordering.** Item 9 turned out to
be a correctness defect affecting Endpoint Inventory as well as Client Map, and
item 11 is the other half of its fix. Cosmetic work on surfaces that state wrong
facts is effort spent making a lie easier to read.

### 1. Tenant selector into persistent chrome — S

Replace the 11 per-panel selectors with one control in the top bar.

- Multi-select: scope is a **set**, never a scalar. Both personas need it — the
  MSP for fleet-wide sweeps, the in-house admin across departments.
- Always visible; never collapsed into a hamburger at any width.
- Reflected in the URL — pasting a link to a colleague is the most common real
  handoff and breaks silently otherwise.
- Panels read the global scope instead of owning a selector.

Touches: `templates/dashboard.html`, `static/js/core.js`, every module that
currently renders its own selector. Expose via `window` **and**
`types/globals.d.ts` per the frontend rules.

Acceptance: one selector in the DOM; changing it re-filters the active panel;
the value survives a tab switch and a reload; `tests/js/` covers the set
semantics.

### 2. Device context chip carried across panels — M

**[corrected]** Traffico *can* filter per device. Every flow record carries
`exporter_ip` (`observability/ingesters/ipfix.py:82`) plus `src`/`dst`. The
dimension exists on every record; it is simply not exposed as a filter. This is
a query parameter and a `WHERE` clause, not a data-model project.

- Selecting a device anywhere sets the chip.
- Traffico, Config, Endpoint read it as a filter.
- Clearing the chip returns to estate-wide.
- **Every panel must state that it is filtered.** A silently scoped panel reads
  as a broken one.

Acceptance: select a device in Dispositivi, switch to Traffico, see only that
device's flows, with the filter stated on screen.

### 3. Situazione — four verdicts, promoted out of Indaga — S

Home leaves the verb group and gets its own slot above the first group header.
Renamed to state its job.

Four full-width verdicts, each a sentence, not a KPI tile:

```
OK    Backup       All 47 devices backed up, last run 04:12
WARN  CVE          2 new advisories affect 3 devices  ->
OK    Raggiungib.  All sites responding
OK    Drift        No config changes since yesterday
```

Green states are terminal: no drill-down, no chart. Only non-green expands.
The healthy case costs zero attention — this is what serves the morning-sweep
scene, and it makes the NOC-wall mode free later (see item 7).

### 4. Command palette (Ctrl+K / ⌘K) — M

Three entry kinds, in priority order:

1. **Destinations** — every tab, fuzzy-matched.
2. **Objects** — devices, clients, MACs, IPs. Typing `192.0.2.10` sets the
   context chip from anywhere.
3. **Verbs** — `backup switch-01`, `export audit`. Executes, does not navigate.

This is what makes hierarchy free: deep grouping costs the power user nothing
when typing a name beats clicking.

Also ship `?` for the shortcut sheet, plus `/` (focus panel search) and `Esc`
(close drawer, then clear the chip). **Ship `?` or ship no shortcuts** — an
undiscoverable shortcut helps only the person who wrote it.

### 5. Demote FortiGate / WLC / HA to device facets — S

They become tabs on a selected device rather than nav items. 23 top-level
surfaces become 20, and each lands where the mental model expects it.

Touches `LAZY_TAB_SCRIPTS` in `core.js` — a module binding controls in another
tab needs an entry for that tab too, or the tab is dead when opened cold.
`tests/test_lazy_tab_scripts.py` checks both halves; do not narrow its scope.

#### Status: half done — the demotion shipped, the replacement did not

The three tabs are gone from the sidebar (23 -> 20) and their panels are intact:
`LAZY_TAB_SCRIPTS` still maps all three, the dispatch still fires, and
`tests/test_lazy_tab_scripts.py` passes. They are registered in the command
palette under a *Facets* group.

**But the palette is currently their only entry point.** A grep for
`data-switch-tab="tab-fortigate|tab-wlc|tab-redundancy"` or a `switchTab` call
from a device row returns nothing. That contradicts this plan's own trap: *the
palette serves people who know the name, it does nothing for discovery.* An
engineer who used the FortiGate tab yesterday finds it gone with no visible way
back — a regression in perception even though nothing is broken.

Constraint that shapes the fix: **there is no device detail view yet.**
`tab-devices` has no detail panel, so "put the facets on the device page" means
building the page first.

#### Decision: ship B now, keep A as the target

**B — capability chip on the inventory row (S, do this).** Each device row gains
a *Strumenti* column carrying a chip per capability its type supports:
`FortiGate` and `HA` on a FortiGate, `WLC` on a controller, nothing on a plain
switch. The chip opens the existing panel with the device pre-selected.

- One template plus one module. Panels, lazy map and dispatch stay untouched.
- Closes the regression immediately rather than when the detail view lands.
- **Not throwaway:** the device-type -> capability mapping it introduces is
  exactly what A needs later to decide which facet tabs to render.
- Chips are `data-action` plus a delegated listener, never inline `onclick`.
- Labels need `it` and `en` entries in `i18n.js`.

**A — facet tabs inside device detail (L, the target).** Selecting a device
shows `Panoramica | Config | Interfacce` plus vendor-conditional `FortiGate` /
`WLC` / `HA`. This is item 5 as originally written, and where the context chip
from item 2 naturally lands. It waits for the device detail view.

**Required either way:** the destination panel must state which device it is
showing. Someone arriving by palette today lands on a surface that never names
its subject, which is what makes that route feel broken rather than fast.

### 6. Rename `Gruppi`; fix the error string — S

- `Gruppi` -> **Tenant** (MSP) or **Reparti** (in-house); pick one neutral term.
  `Siti` -> **Sedi** or **Connettività**.
- Fix `routers/deps.py:104` to say *Group*, not *Site*. It is the one message
  that teaches users the model, and it currently teaches the wrong one.
- Identifiers stay English; user-facing strings need both `it` and `en` entries
  in `static/js/i18n.js`.

### 7. Three layout intents — L

"Responsive" is an outcome, not a layout decision. Fluid-squeezing one desktop
layout produces a rack-side view where the engineer scrolls eleven columns to
find a switch port.

| Width | Scene | Intent | Sidebar |
| :--- | :--- | :--- | :--- |
| `< 768` | rack-side, standing, one hand | a different product (below) | bottom bar, 4 icons |
| `768–1279` | half-screen beside a terminal | single column, full fidelity | icon rail, expands |
| `>= 1280` | full-screen desk | two columns: content + evidence | full labelled sidebar |

**More width does not mean more columns.** Cap at two; beyond that scale type
and whitespace, and stop truncating hostnames, IPs and serials.

**The `< 768` product** — confirmed task: MAC or IP -> switch port -> VLAN.

```
Tenant: Customer B
[ search: MAC, IP or hostname ]     <- autofocus, large tap target

AA:BB:CC:DD:EE:FF
  PORTA   switch-01 Gi1/0/14        <- the answer, largest type
  VLAN    120 — Voice
  VISTO   2 min fa                  <- staleness, always
  [ Diagnosi completa -> ]
```

- Accept a MAC in any format (colons, hyphens, dots, bare hex); normalise on
  input rather than rejecting. The engineer is copying off a label, not matching
  a regex.
- **Always show staleness.** "2 min fa" vs "3 giorni fa" is the difference
  between a fact and a guess; ARP data goes stale quietly.
- No tables, no tabs, no sidebar. The other scenes do not exist at this width.

**NOC wall is not a breakpoint and is not built now.** It is an intent — read at
four metres, never touched. If item 3's verdict layout is prose + status colour,
wall mode is "hide the chrome, scale the root font": ~15 lines of CSS behind a
query param, buildable in an hour the day a customer asks. Design so that stays
true; build nothing.

### 8. Streaming SSH progress, then skeletons and empty states — M

Confirmed: **the SSH round-trip is the slowest thing in the app.** So streaming
progress is the work; skeletons are secondary.

| Class | Example | Treatment | Never |
| :--- | :--- | :--- | :--- |
| `< 300ms` | tab switch, filter, sort | nothing, just render | a spinner |
| `0.3–3s` | config parse, flow query | skeleton matching final layout | centred spinner on blank |
| `> 3s` | SSH, provisioning push, backup | streaming progress, named step | indeterminate bar, no text |

**The transport already exists.** `/api/ws-terminal/{ip}`
(`routers/commands.py:327`) carries live SSH output to the browser. Emit named
progress steps over the same channel — no SSE, no polling, no second protocol to
secure and tenant-scope. `_ssh_failure_hint()` (`routers/commands.py:293`)
already produces human-readable failure reasons; that text belongs in the
progress stream, not only in a final error toast.

Never optimistic-UI a config write. A push is a conclusion the app is making
about the network, and conclusions ship their evidence.

Also in this item:

- **Cold tabs render empty while their module downloads.** `core.js` correctly
  swaps the panel before awaiting the lazy module, but nothing indicates the
  download; empty reads as broken. Add a skeleton in the panel.
- **Empty states say why** (principle 5): *no data yet* (with the action that
  collects it), *filtered to nothing* (with the filter to clear), *not permitted
  in this tenant*. Today all three render as the same blank table, and the third
  silently teaches users the feature is broken.
- `showToast('Errore di caricamento modulo', 'error')` in `core.js` is a
  hardcoded Italian string — route it through `i18n.js`.

### 9. Retire the Client Map view — S, and it is a correctness item

Client Map (MAC <-> IP) is superseded by Endpoint Inventory **and displays
incorrect information** (confirmed in session). That makes this a correctness
removal, not a tidy-up: a surface stating wrong facts is worse than no surface,
because it spends the trust the rest of the product is built on.

**[corrected]** It is already a view pill inside Endpoint Localisation
(`templates/dashboard.html:1265`, `data-loc-view="clientmap"`), not a top-level
tab, so removal costs nothing in the nav. `static/js/client-map.js` is ~870
lines and mostly view code (`locSwitchView`, tenant pills, rendering).

**Remove the view. Keep the logic other tabs use.** The ARP data feeds
`observability/correlator.py`, `observability/flowpath.py`,
`observability/timeline.py` and Endpoint Inventory itself. Deleting the route
would break four consumers to tidy one pill.

`ui_tab_overlap_analysis.md` notes `client-map.js` serves **both** MAC Tracker
and Client Map — split the module rather than deleting it wholesale.

#### Root cause: `arp_entries` keeps stale bindings and no read path filters them

**Investigated and reproduced 2026-08-26.** The fault is in the shared data
path, not in the view — and it affects **Endpoint Inventory too**, which
invalidates the "Endpoint Inventory does it better" premise this item started
from.

`record_arp_entries()` upserts on `(mac, ip, source_ip)`
(`collectors/mac_history.py:373`). When a client changes IP — a new DHCP lease,
a VLAN move — the new binding **INSERTs a new row**; the old row is never
deleted and simply stops being updated. It survives until `prune()` removes it
at the retention horizon. `arp_entries` is therefore an append-only *history*,
and nothing in it marks which binding is **current**.

Both read paths treat every surviving row as equally valid:

- **`endpoint_inventory()`** collects `ips = sorted({...})` over every row for
  the MAC (`mac_history.py:800`). The ARP query above it does not even
  `SELECT last_seen`, so it *cannot* order by recency.
- **`client_map()`** returns one row **per binding**, not per client, so one
  client with three historical IPs is three rows.

Reproduction — one MAC, scan at `192.0.2.10` yesterday, scan at `192.0.2.11`
today, everything else held constant:

```
arp_entries rows for one MAC after two scans: 2
   ip=192.0.2.11   last_seen=2026-08-26T18:31:06+00:00
   ip=192.0.2.10   last_seen=2026-08-25T18:31:06+00:00

endpoint_inventory -> ips  : ['192.0.2.10', '192.0.2.11']
endpoint_inventory -> flags: ['MULTI-IP', ...]
first IP shown to the user : 192.0.2.10        <- the STALE one

client_map rows for one client: 2              <- duplicate rows, one client
```

The scan *did* work. The write path is correct. The read paths are wrong.

Two consequences worth stating plainly:

- **The stale IP sorts first.** `sorted()` is lexicographic, so `192.0.2.10`
  precedes `192.0.2.11`. The value the eye lands on is the obsolete one. This
  is why the surface "shows info wrong" while a scan appears to have succeeded.
- **`client_type` can be inherited from an address the client no longer holds.**
  The assignment lookup (`mac_history.py:826`) takes the first match over *any*
  IP in `ips`, stale ones included.

#### The fix: newest scan wins, per source

A genuinely multi-homed or dual-stack host legitimately holds several IPs **at
the same time**, and `MULTI-IP` is a true flag for it. So the rule cannot be
"one IP per MAC". **Decided in session:**

> A binding is **current** when its `last_seen` equals the newest `last_seen`
> among rows sharing its `(mac, tenant, source_ip)`.

Why this shape, and why it needs no tuning knob:

- **Concurrent IPs survive.** One scan writes every binding it saw with the
  same timestamp, so a dual-stack host keeps both rows and `MULTI-IP` stays
  truthful.
- **A changed IP drops out immediately**, at the very next scan, without
  waiting for retention.
- **Per `source_ip`**, so a client legitimately reachable through two gateways
  keeps one current binding from each rather than one gateway silently winning.
- No window to configure, therefore no wrong value to set and no quiet
  reintroduction of the bug.

Read-path changes this implies:

- `endpoint_inventory()` must `SELECT last_seen` in its ARP query — today it
  does not, which is why it *cannot* order by recency — and keep only current
  rows when building `ips`.
- `client_map()` must return **one row per client**, not per binding.
- The `client_type` assignment lookup (`mac_history.py:826`) must consider only
  current IPs, so a category is never inherited from an address the client no
  longer holds.
- `MULTI-IP` keeps its meaning: several *current* IPs, not several historical
  ones.

Regression test must cover: IP change (old drops), dual-stack (both survive),
two gateways (one current each), and a MAC whose only binding is older than the
newest scan of a *different* MAC (must not be wrongly excluded).

Related, found in the same pass and **not** yet investigated: the UPDATE branch
of `record_arp_entries()` writes `tenant=?` while `tenant` is not part of the
upsert key. The same `(mac, ip, source_ip)` observed under a different tenant
would overwrite the field. Tenant is an authorization boundary, so this needs
its own verification.

#### Open: sequencing

Now that the fault is known to be server-side, deleting the view alone would
*hide* the bug while `/api/arp/client-map` — a registered MCP tool
(`ai/mcp_server.py:148`) — keeps serving the same stale bindings to the AI
assistant, which will state them confidently with no human eye on the result.
That contradicts the principle that every conclusion ships its evidence.

Endpoint Inventory is affected by the same defect, so removing Client Map does
not leave a correct surface behind.

Revised order, and **this now precedes the cosmetic items**:

1. Decide the recency window (product call).
2. Fix the read paths in `mac_history` — `endpoint_inventory()` and
   `client_map()` — with a regression test covering the IP-change scenario
   reproduced above.
3. Verify the `tenant` overwrite in `record_arp_entries()`.
4. *Then* delete the Client Map view, as genuinely redundant rather than as a
   way to stop seeing the bug.

### 10. `Preview` tag on single-client L2 + L3 reporting — S

Single-client L2+L3 reporting has never run against real hardware. It ships in
the same visual register as validated features, which quietly makes a claim the
product cannot support.

The nav already uses this convention — `Incidenti (preview)` — so **follow it**
rather than inventing a second one.

- Pill beside the feature title, in the **caution** colour, not the accent.
  It is a warning, not a promotion.
- Say why on hover/focus: "Non ancora validato su hardware reale. I risultati
  possono essere incompleti." Specific beats vague; an engineer can calibrate
  against that sentence.
- **The exported report carries the tag too.** A PDF outlives its screen, and a
  preview finding pasted into a ticket otherwise loses its caveat.
- Do not disable or bury it. Preview means honest, not hidden — real use is what
  produces the validation it is waiting for.
- **Write the exit condition down beside the flag**: *validated against real
  hardware*. A Preview tag with no stated way out is still there in four years,
  by which time users have learned to ignore it.

### 11. Time-range filter — deliberate history instead of mixed history — M

Proposed in session, and it is the other half of item 9's fix. Item 9 makes the
default view show only what is **current**. This item gives the history back as
something you **enter on purpose**.

The bindings are not worthless — they are a real record of where a client was
and when. They are only harmful when silently mixed into a view claiming to
describe *now*. A range filter separates the two questions:

- **Default — no range set:** current bindings only, per the rule in item 9.
  This is the answer to "where is this client".
- **Range set (date + hour, from/to):** every binding whose
  `[first_seen, last_seen]` overlaps the window, with the mode stated on
  screen. This is the answer to "where was this client on Tuesday afternoon".

Applies to Endpoint Inventory, the ARP search, and client history — the same
control, the same semantics, so the concept is learned once.

Design constraints:

- **The mode must be unmissable.** A historical view that looks like the live
  one recreates exactly the confusion item 9 removes. When a range is active,
  say so in the panel, not only in the control.
- **Hour granularity, not just date.** A lease change and a port move both
  happen inside a working day; a date-only filter cannot separate them.
- **Bound the picker by `retention_days`.** Asking for a window older than
  retention must say *"outside the retention window (N days)"* rather than
  returning an empty table — principle 5, and otherwise the feature silently
  lies about the past being empty.
- **Reflect the range in the URL**, so a "this is what it looked like at 14:00"
  link can be pasted into a ticket.
- **The MCP tool takes the same parameter**, defaulting to current. The AI
  assistant must be able to answer historical questions explicitly and must
  never answer a present-tense question from historical rows.
- **Add the range to the `endpoint_inventory` cache key.** `_inventory_stamp()`
  versions the *data*, not the *question*; without the range in the key a past
  query and a live query collide.

Cheap corollary once this exists: a client's IP history becomes a legitimate
answer rather than a symptom, so `client_history()` and the timeline gain a
shared vocabulary with the inventory.

### 12. Resolved domain names — an extension of the FortiGate log path — S

Today a flow row shows `192.0.2.50` where the FortiGate GUI shows
`192.0.2.50 (github.com)`. The name is not missing from the wire; it is missing
from the allowlist.

**This is not a new subsystem.** Everything needed already exists:

- `routers/fortigate.py:66-70` already fetches FortiGate logs by category,
  building `log/{device}/{type}/{subtype}` with
  `forward | local | virus | webfilter | ips | ...`.
- `observability/fieldmap.py:19-20` already parses `subtype` and `eventtype`,
  and `normalize.py:178` already carries `subtype` through.

Two changes:

1. **Widen `_KV_RE`** (`observability/fieldmap.py:19`) to capture `hostname`,
   `dstname` and `qname` alongside the existing keys, and return them from
   `extract()`. FortiOS emits `hostname=` / `dstname=` on inspected sessions.
2. **Request the `dns` subtype** in the log fetch, and keep `qname` plus the
   answered address.

Coverage, honestly stated:

| Source | Covers | Note |
| :--- | :--- | :--- |
| `hostname` / `dstname` on forward logs | inspected sessions only | needs webfilter, appctrl or SSL inspection; plain policy traffic carries no name |
| `dns` subtype logs (`qname` + answer) | everything the client actually resolved | the real answer, and the pipeline already accepts it |
| FQDN address objects (`fortigate_service.py:459`) | names configured as objects | already collected, narrow coverage |

**The mapping is time-bound and many-to-one — treat it like the ARP bindings.**
CDNs and shared hosting put dozens of names on one address, and a resolution
expires. Store *which client resolved which name, and when*; never a global
reverse map, or a name gets attributed to a client that never asked for it.
That is the same defect as item 9 in a different table, so it reuses item 11's
range semantics rather than inventing its own.

Display rule: the name is an annotation, never a replacement. Show
`192.0.2.50 (github.com)`, keep the address sortable and copyable, and say
nothing when no resolution is known rather than guessing from reverse DNS.

(GeoIP country flags in the FortiGate GUI are a separate dataset and are not
part of this item.)

### 13. Colour the config diff — S

The config diff renders additions and removals in the same colour, so the only
signal is the leading `-` / `+` character. A diff is scanned, not read; the
colour is what makes a change visible before it is parsed.

- Removed lines red, added lines green, context unchanged in body colour.
- **Colour is the second signal, never the only one.** Keep the `-` / `+`
  glyph, so the diff still reads for a colour-blind user and survives copy and
  paste into a ticket. Roughly 8% of male users cannot rely on red/green.
- Take the hues from `DESIGN.md` semantic tokens, not new literals, and verify
  both themes: the light rendition is where contrast fails first.
- Tint the row background lightly rather than only the glyph — a full-width
  band is what makes a block of changes readable at a glance.
- The diff already redacts secrets (`***REDACTED***`); make sure the colour
  pass does not reintroduce the raw value by rendering a pre-redaction string.

### 14. Traffic tab defects — M

Reported as "many things do not work properly". Two are confirmed from the
code; the rest need specifics before they can be listed.

#### 14a. The VLAN column shows fabricated numbers — correctness

`_synthetic_vlan()` (`routers/observability.py:401`) returns
`100 + sha1(tenant)[:2] % 900` — a deterministic hash of the **tenant name**,
in the range 100–999 — whenever no ARP binding is known for an IP. Top Talkers
then renders it in the `VLAN` column beside genuinely observed VLANs, marked
only by a dim `*` in `--text-muted` with a tooltip
(`static/js/observability.js:1121`).

The result is a number that looks exactly like a real VLAN ID sitting in a
column labelled VLAN. An engineer reads it and goes looking for that VLAN on
the switch. It does not exist.

This contradicts the project's own rule, stated in `observability/fieldmap.py`:
*"Ciò che il messaggio non contiene resta None: nessun valore inventato."* The
normaliser refuses to invent values; this router invents one and renders it as
fact.

**The API already carries the answer.** `_vlan_for()`
(`routers/observability.py:494`) returns `(vlan, is_real)`, and every node and
edge already ships `vlan_real` alongside `vlan`. The backend knows the value is
fabricated; the frontend receives that flag and renders the number regardless.
So this is a rendering fix plus two leaks, not a redesign.

**Keep `_synthetic_vlan()`.** It is load-bearing: the flowgraph uses the value
to cluster nodes, and removing it would break grouping for every IP without an
ARP binding. It stays an internal layout key. What changes is that it stops
being reported as observed state.

##### Fix specification

**1. Top Talkers VLAN cell — `static/js/observability.js`**

Render the VLAN only when `vlan_real` is true; otherwise an em dash. Delete the
`*` disclosure span at line 1136 and the inline one at 1121 — once nothing
fabricated is displayed, there is nothing left to disclose.

```
vlan_real === true   ->  "10"
vlan_real === false  ->  "—"
```

Applies to every place the flowgraph VLAN is rendered, not only Top Talkers:
grep `vlan_real` and treat each hit.

**2. Tenant summary VLAN list — `routers/observability.py:541-543`**

`tenant_vlans` is built from `node_vlan[ip][0]` without checking the flag, so
fabricated VLANs enter the reported list. The `else` branch is worse — with no
nodes it returns `[_synthetic_vlan(tenant_name)]`, a list whose only element is
invented.

- Filter to `node_vlan[ip][1] is True`.
- Replace the fallback with `[]`. No nodes means no visible VLANs, which is a
  true statement; a synthesised one is not.

**3. "Visible VLANs" count — `static/js/observability.js:1122`**

Counts `t.vlans.length`, which today includes fabricated entries. Once (2)
filters the list this follows automatically — verify rather than edit.

##### Acceptance

- A flow whose IP has **no** ARP binding shows `—` in the VLAN column, and the
  tenant summary does not list a VLAN for it.
- A flow whose IP **has** an ARP binding still shows its real VLAN.
- The flowgraph still groups unbound nodes together — i.e. `_synthetic_vlan()`
  is still doing its layout job, unchanged.
- A tenant with zero visible nodes reports `Visible VLANs: 0`, not `1`.
- No `*` disclosure marker remains anywhere in the Traffic views.

##### Why not just make the asterisk louder

Because the value is still fabricated. A stronger marker on an invented VLAN ID
asks the user to remember which numbers are real — exactly the cognitive load
the product exists to remove. It also fails the NOC-wall and rack-side scenes,
where a hover tooltip cannot be reached at all.

#### 14b. Duplicate tenant control — item 1, half-migrated

The Traffic panel carries an `ALL TENANTS` button while the new global top bar
already shows the tenant selector. Two controls for one authorization boundary,
disagreeing in vocabulary, on one screen. This is exactly the duplication item 1
exists to remove — the global selector shipped, the per-panel ones did not all
come out.

##### Fix specification

- **Audit, do not spot-fix.** `ui_tab_overlap_analysis.md` counted 11 tenant
  selectors before item 1; grep every panel for a tenant control and list what
  survives. Fixing only the one that was noticed leaves the rest to be
  rediscovered one screenshot at a time.
- **The global selector is the only writer.** Panels read scope; they never own
  a control that sets it.
- **"All tenants" is a value of the global selector**, not a separate button.
  An unscoped admin selects it there; a scoped user must not be offered it at
  all, since it would imply access they do not have.
- **Acceptance:** exactly one tenant control exists in the DOM on every tab;
  changing it re-filters the active panel; `tests/js/` covers the set
  semantics, and a scoped user is never offered a scope wider than their own.

#### 14c. Unspecified

"Many things" implies more than the two above. Each needs the symptom, the view
(Overview / Flows / Search / Anomalies) and what was expected, or it cannot be
distinguished from a data gap — a listener not configured, or a window with no
traffic in it, both of which look like a broken panel.

---

## Traps

Each one comes from a decision that is easy to make wrongly here.

- **Do not make the nav groups an accordion that closes siblings.** Users scan
  for a label they half-remember; auto-collapse turns scanning into search.
- **Scope must fail loud, not silently filter.** An empty panel says *"Nessun
  dispositivo in Customer B"*, never an empty table.
- **Hide role-gated items, never flicker them.** Hide `requires-admin` for
  viewers, but an item that appears and disappears for the same user destroys
  spatial memory.
- **The palette is not an excuse to keep bad IA.** It serves people who know the
  name; it does nothing for discovery.
- **Actions live with their object.** Global toolbars carry global actions only,
  and a destructive action never sits in a row menu beside `View` — Fitts's law
  makes adjacent targets equally easy, which is wrong when one is idempotent and
  one reboots a firewall.
- **Export belongs at the end of a report, not in its header** — a toolbar puts
  the terminal action first in reading order.
- **Audit state must survive a tab switch.** A checklist that resets is data
  loss wearing a UX costume.
- **The icon rail needs tooltips *and* `aria-label`.** Icon-only nav without
  labels is a memory test and fails the WCAG 2.1 AA target.
- **Two columns means two scroll regions** — verify focus order with Tab, not a
  mouse.
- **Fix theme literals at token level first.** The light rendition is where
  contrast fails first; layout work will otherwise propagate the dark-only
  colour literals further.
- **Panel layers, in reading order: verdict, then evidence, then controls.**
  Most panels today lead with controls, putting the least informative element in
  the highest-attention position.

---

## Verification

Per `AGENTS.md` and `docs/development.md` §6, before each commit on this branch:

```sh
uv run pyrefly check                          # 0 errors
uv run python scripts/check_frontend.py       # static/js or templates/ changed
uv run pytest tests -n 4                      # all green
graphify update .
```

Frontend specifics that apply to most items here:

- `core.js` globals are `let`, so they are **not** `window` properties. Reading
  them as `window.X` yields `undefined`, and a `|| []` fallback hides it.
- Cross-module exposure means `window.X = ...` **and** an entry in
  `types/globals.d.ts`.
- Delegated listeners must bind to an id that exists in `dashboard.html`.
- No inline handlers: use an id or `data-action` plus a delegated listener.
- A module binding controls in another tab needs a `LAZY_TAB_SCRIPTS` entry for
  that tab too.

## Versioning

Items 1–10 are new features and architectural UI change: **MINOR** bump when the
first lands. `core/version.py` is the single source of truth; `pyproject.toml`
must match. This plan document alone changes no version.
