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

Sequenced by leverage per unit of effort. Items 1, 3, 5, 6, 9 and 10 are small
and mutually independent — a shippable first pass, two of them deletions.

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

#### Open: where is the wrongness?

The join is **server-side**, in `mac_history.client_map()`, reached via
`/api/arp/client-map` (`routers/arp.py:62`). The same endpoint is a registered
MCP tool (`ai/mcp_server.py:148`).

So the fix depends on which layer is at fault, and the two outcomes differ:

- **Wrong rendering only** — deleting `client-map.js`'s view half resolves it
  fully. Nothing else is affected.
- **Wrong join in `mac_history.client_map()`** — deleting the view *hides* the
  bug while the MCP tool keeps serving the same bad data to the AI assistant,
  which will state it confidently and without a human eye on it. That is a
  regression in everything except appearances, and it contradicts the product
  principle that every conclusion ships its evidence.

**Do not delete the view until this is answered.** If the join is at fault,
quarantine or fix the MCP `client_map` tool in the same change; the endpoint
must not outlive the surface that was making its errors visible.

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
