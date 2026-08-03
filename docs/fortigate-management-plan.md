# FortiGate Management tab

## Context

The hidden tab *"FortiGate LIVE — token e oggetti firewall"* becomes a normal tab named
**Fortigate Management**, surfacing most of the FortiGate read APIs and getting a UI
refinish.

Exploration showed the backend already outruns the UI by a wide margin:

- [routers/fortigate.py](../routers/fortigate.py) exposes ~20 endpoints; the tab uses **6**.
  Unwired but already routed: interfaces, ARP, DHCP leases, device-inventory, policy-stats,
  policy-lookup, sessions, routes, traffic logs, WiFi clients, WiFi APs, full-config,
  diagnose-client.
- Three service functions have **no route at all**: `get_vpn_tunnels`
  ([fortigate_service.py:449](../services/fortigate_service.py#L449)), `get_ha_status`
  ([:208](../services/fortigate_service.py#L208)), `get_ha_checksums`
  ([:212](../services/fortigate_service.py#L212)).
- The tab's three view pills use `.ca-pill`, but that CSS is scoped `#tab-config`
  ([dashboard.css:834](../static/css/dashboard.css#L834)) — **they currently render
  unstyled**. Pre-existing bug, fixed here.

So "most API features" is mostly a wiring job, not new backend.

### Two gaps carried in from the client-diagnosis work

A review of the 13 client-diagnosis items found 11 fully wired to the UI. Two are not,
both inside *"Phase 3b: parameterise log category + surface policy hit counters"*:

| Gap | State |
|---|---|
| Policy hit counters | `get_policy_stats` ([:354](../services/fortigate_service.py#L354)), route `/api/fortigate/{ip}/policy-stats`, MCP tool `fortigate_policy_stats` all exist. **Zero UI.** |
| Log category | `get_traffic_logs` takes `log_type`/`log_subtype`/`cli_category` ([:510-511](../services/fortigate_service.py#L510-L511)), but `FgtLogQuerySchema` ([fortigate.py:60](../routers/fortigate.py#L60)) carries only `log_device`. **Unreachable over HTTP.** |

Both are closed by this plan and are sequenced first (Phase 1).

## Decisions locked with the user

| Question | Decision |
|---|---|
| Write access | **Read-only.** No PUT/POST to FortiOS cmdb, no policy edits, no session clearing. |
| UI shape | **Sub-tabs**, reusing the existing `.ti-subtab` bar (Traffico / Topologia / Localizzazione Endpoint). |
| New read APIs | **All four groups**: system resources + SD-WAN, firewall groups/VIPs/pools, security profiles + admins, config revisions + certificates. |
| Gating | **Always visible, admin-only.** The `fortigate_preview_enabled` flag and its settings endpoints are deleted, not kept as a shim. |

---

## Phase 1 — Close the two carried-in gaps

Lands first, independently useful, and both pieces are consumed by Phase 3's UI.

### 1.1 Expose the log category over HTTP

`FgtLogQuerySchema` gains three optional fields mirroring the service defaults:

```python
log_type: str = "traffic"      # traffic | event | utm
log_subtype: str = "forward"   # forward | local | webfilter | virus | ips | ...
cli_category: str = "traffic"  # categoria per il fallback CLI
```

Passed straight through to `get_traffic_logs`. Defaults are the current values, so the
existing call in [client-map.js](../static/js/client-map.js) and the MCP tool keep
today's behaviour.

**Parity impact:** `FgtLogQuerySchema` is a golden schema and is not in
`ALLOWED_CHANGED_SCHEMAS`. Adding optional fields with defaults changes the schema, so
`test_migrated_schemas_identical` and `test_every_schema_identical` will fail until
`FgtLogQuerySchema` is added to both `ALLOWED_CHANGED_SCHEMAS` tuples in
[test_router_parity.py](../tests/test_router_parity.py) with a comment stating the
addition is optional-with-defaults and therefore backwards compatible.

### 1.2 Merge hit counters into the policy view

`get_policy_stats` returns runtime counters keyed by policy id; `get_firewall_policy_objects`
returns the config rows. A new service function `get_policies_with_stats(device)` calls both
and joins on `policyid`, so the Firewall → Policies table shows hits / bytes / active
sessions as columns with a "never hit" marker on zero-hit enabled policies.

The join is **server-side, not in the renderer**: this repo has no JS test runner — the
frontend is checked grep-style through `frontend_source()`
([test_helpers_frontend.py](../tests/test_helpers_frontend.py)) — so logic put in JS cannot
carry a real test. In Python it gets one. It also halves the browser's requests and drops
into the dataset registry as a single entry.

Route `GET /api/fortigate/{ip}/firewall/policies-with-stats` sits under the already
allowlisted `/api/fortigate/{ip}/firewall` prefix, so it needs **no parity change**.

Zero-hit detection is the point of the feature (dead policies are audit findings), so it
carries the phase's runnable check: a policy present in config but absent from stats, and
one present in both with `hit_count: 0`.

---

## Phase 2 — New read-only service functions and routes

Twelve new service functions, each 2–4 lines over the existing `api_get` / `api_get_cmdb`
transport, plus a route for the one that already exists. No new transport code.

"user" in the Auth column means the existing `Depends(get_current_user)`.

| Function | FortiOS path | Route | Auth |
|---|---|---|---|
| `get_system_resources` | `monitor/system/resource/usage` + `monitor/system/time` | `GET /api/fortigate/{ip}/system/resources` | user |
| `get_ha` | `monitor/system/ha-status` + `monitor/system/ha-checksums` | `GET /api/fortigate/{ip}/system/ha` | user |
| `get_admins` | `cmdb/system/admin` | `GET /api/fortigate/{ip}/system/admins` | **admin** |
| `get_banned_users` | `monitor/user/banned` | `GET /api/fortigate/{ip}/system/banned-users` | user |
| `get_config_revisions` | `monitor/system/config-revision` | `GET /api/fortigate/{ip}/system/config-revisions` | user |
| `get_certificates` | `monitor/system/available-certificates` | `GET /api/fortigate/{ip}/system/certificates` | user |
| `get_vpn_tunnels` *(exists)* | `monitor/vpn/ipsec` | `GET /api/fortigate/{ip}/vpn/tunnels` | user |
| `get_sdwan_health` | `monitor/virtual-wan/health-check` | `GET /api/fortigate/{ip}/sdwan/health` | user |
| `get_address_groups` | `cmdb/firewall/addrgrp` | `GET /api/fortigate/{ip}/firewall/address-groups` | user |
| `get_service_groups` | `cmdb/firewall/service/group` | `GET /api/fortigate/{ip}/firewall/service-groups` | user |
| `get_vips` | `cmdb/firewall/vip` | `GET /api/fortigate/{ip}/firewall/vips` | user |
| `get_ip_pools` | `cmdb/firewall/ippool` | `GET /api/fortigate/{ip}/firewall/ip-pools` | user |
| `get_security_profiles` | `cmdb/antivirus/profile`, `cmdb/ips/sensor`, `cmdb/webfilter/profile`, `cmdb/application/list` | `GET /api/fortigate/{ip}/firewall/security-profiles` | user |

`get_ha` and `get_system_resources` each merge two calls into one response so the Overview
sub-tab makes one request per card instead of four.

`monitor/virtual-wan/health-check` is confirmed by
[docs/reference/fortios/rest-api.md:29](reference/fortios/rest-api.md#L29). The other paths
are standard FortiOS 7.x but are **not** covered by the local reference — each needs a
smoke check against a real box before the phase is called done.

### Security constraints

- **`get_admins` projects fields explicitly** via `api_get_cmdb(fmt=...)`:
  `name|accprofile|trusthost1|trusthost2|two-factor|comments`. The `password` field must
  never leave the service, regardless of what FortiOS returns. Route is `require_admin`.
  A test asserts the projection string contains no password-ish key and that the route
  dependency is `require_admin`.
- Certificates come from the `monitor` endpoint: metadata and expiry only, never private
  key material.
- Everything else keeps today's `get_current_user`; `full-config` keeps `require_operator`.
- All new routes go through the existing `_fgt_device()` scoping check, so per-site
  restrictions apply unchanged.

### Optional-feature degradation

A FortiGate with no SD-WAN configured, no WiFi controller, or a licence that omits a
profile type returns 404, which `_fgt_call` maps to HTTP 502. The **UI** treats a failed
optional dataset as an empty state carrying the error in a `title` attribute — no backend
fallback logic, no try/except ladders in the service.

### Parity impact

`test_no_unexpected_new_paths` requires new paths to match `ALLOWED_NEW_PREFIXES`.
`/api/fortigate/{ip}/firewall` is already allowlisted; add `/api/fortigate/{ip}/system`,
`/api/fortigate/{ip}/vpn` and `/api/fortigate/{ip}/sdwan` to `ALLOWED_NEW_PREFIXES`
(`TestRouterParity`) and `NEW_PREFIXES` (`TestFullParity`).

---

## Phase 3 — Tab rebuild

### 3.1 Rename and de-gate

| From | To |
|---|---|
| `#tab-fortigate-preview` | `#tab-fortigate` |
| `#navFortigatePreview` | `#navFortigate` |
| `static/js/fortigate-preview.js` | `static/js/fortigate-management.js` |
| "FortiGate LIVE — token e oggetti firewall" | "Fortigate Management" |

Deleted outright: `applyFgtPreviewGating()`, `setFgtPreview()`, the toggle at
[dashboard.html:2113](../templates/dashboard.html#L2113), both
`/api/settings/fortigate-preview` handlers ([settings.py:85-96](../routers/settings.py#L85-L96)),
the `fortigate_preview_enabled` setting, the call site at
[core.js:462](../static/js/core.js#L462), and the `preview-badge` span. Nav item keeps
`requires-admin`; the `switchTab` dispatch at [core.js:584](../static/js/core.js#L584)
is renamed.

Removing `/api/settings/fortigate-preview` breaks `TestFullParity.test_path_set_identical`,
because the path is in `openapi_pre_destructure.json`. That filter is applied to *both*
sides, so adding the prefix to `NEW_PREFIXES` covers a removal as well as an addition —
with a comment saying so. The stale entry in `TestRouterParity.ALLOWED_NEW_PREFIXES` is
deleted.

### 3.2 Sub-tabs

Seven, in a `.ti-subtab` bar with `flex-wrap:wrap`, matching the existing pattern at
[dashboard.html:954](../templates/dashboard.html#L954). Unlike Traffico/Topologia these are
*not* separate top-level tab divs — they are panes inside `#tab-fortigate` switched by a
local `fgtSwitchView()`, because they share one target selector and one device context.

| Sub-tab | Views |
|---|---|
| Overview | status, resources (CPU/mem/disk/sessions), HA state + checksum sync, uptime, time |
| Network | interfaces, ARP, DHCP leases, routes, VPN tunnels, SD-WAN health |
| Firewall | addresses, address groups, services, service groups, VIPs, IP pools, policies **+ hit counters**, policy lookup form |
| Traffic | sessions query, traffic logs **with type/subtype selector**, device inventory |
| Security | security profiles, admin accounts, banned users, certificates + expiry, config revisions |
| WiFi | managed APs, WiFi clients |
| Settings | target selector, manage-targets modal, token panel, full-config viewer (operator+) |

The `.ca-pill` rules are re-scoped from `#tab-config` to `#tab-config, #tab-fortigate` in
[dashboard.css](../static/css/dashboard.css), fixing the unstyled pills.

### 3.3 Dataset registry

One declarative map drives every read view:

```js
const FGT_DATASETS = {
  interfaces: { url: ip => `/api/fortigate/${ip}/interfaces`, cols: [...] },
  sessions:   { url: ip => `/api/fortigate/${ip}/sessions`, method: 'POST',
                body: () => ({ src_ip: ..., count: 100 }), cols: [...] },
  ...
};
```

`cols` entries are `[key, i18nLabelKey]`, exactly the shape of the existing
`FGT_OBJ_COLUMNS` ([fortigate-preview.js:8](../static/js/fortigate-preview.js#L8)) — this
is that idea generalised, not a new abstraction. One `loadFgtDataset(key)` and one
`renderFgtDataset(key)` replace what would otherwise be ~20 near-identical function pairs.

Adding a view later costs three lines.

### 3.4 Renderer contract

Service responses are `{source, data, api_error?}` where `data` is a **list**, a **dict**,
or **raw CLI text** when the SSH fallback fired. The current renderer
([fortigate-preview.js:250](../static/js/fortigate-preview.js#L250)) assumes list and
breaks on the other two. The new one handles all three:

- list → column table per `cols`
- dict → two-column key/value table
- string → `<pre>` block

When `source === "ssh"` it shows a badge saying REST failed, with `api_error` in the
`title`. This is the difference between "the firewall says no" and "we fell back to
scraping the CLI", and today the UI hides it.

Escaping stays `escapeHtml(jsStr(x))` on every FortiGate-derived string, per the
convention already followed in this file.

### 3.5 i18n

New label keys go into both `it` and `en` blocks of
[static/js/i18n.js](../static/js/i18n.js). Column labels follow the existing
`colFgt<Area><Field>` naming.

---

## Testing

Beyond the phase checks already named:

- **Dataset registry integrity** — every `FGT_DATASETS` entry has a non-empty `cols`, and
  every `url` builder produces a path that exists in the OpenAPI schema. Catches a typo'd
  endpoint at test time instead of in the browser.
- **Admin projection** — `get_admins`' `format` string contains no password-ish key, and
  the route's dependency is `require_admin`.
- **Zero-hit join** — Phase 1.2, described above.
- **UI guard** — `test_ui_revamp.py` has four stale comments naming `fortigate-preview.js`
  ([:963](../tests/test_ui_revamp.py#L963), [:986](../tests/test_ui_revamp.py#L986),
  [:1085](../tests/test_ui_revamp.py#L1085), [:1101](../tests/test_ui_revamp.py#L1101))
  to update. Its two real assertions — `apiFetch('/api/fortigate/tokens')` and
  `apiFetch('/api/fortigate/token'` — still hold, since the token panel survives in the
  Settings sub-tab.

Gate for every phase, per [CLAUDE.md](../CLAUDE.md):

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

## Status

Shipped: seven sub-tabs, thirteen read-only service functions, fourteen routes, all
driven by the `FGT_DATASETS` registry. Read-only throughout — no cmdb writes anywhere.

### Traffico → Log — resolved

Selecting *forward* used to need `RIGHE=10000` to show anything, and a date range
returned nothing. Three separate FortiOS behaviours, now measured on 7.4 and written up
in [reference/fortios/logging.md](reference/fortios/logging.md#rest-get-apiv2logdevicetypesubtype):
the log search is **asynchronous** (a first response can be `ready: false` with zero rows),
the path subtype does **not** filter (only `filter=subtype==`), and date ranges have **no**
`>=`/`<=` and **no** OR, so a range is walked one `date==` per day. Handled by
`_log_search()` and `_log_range_days()` in `services/fortigate_service.py`.

The `sottotipo filtrato` badge means the client-side reconciliation had to fire — on 7.4 it
should stay hidden, because the server-side filter is honoured. If it appears, that FortiOS
build ignores `filter=subtype==` too.

### Still unverified against hardware

These paths have never returned a non-empty answer on a real box; a wrong path degrades
silently into an empty panel. **An empty panel is not automatically a failure** — a box
without SD-WAN, without a WiFi controller, or on a licence lacking IPS legitimately 404s
and renders an empty state with the reason in the `title` attribute. Hover it to tell a
real absence from a typo.

| Sub-tab → view | Path |
|---|---|
| Panoramica | `monitor/system/resource/usage`, `monitor/system/time` |
| Panoramica | `monitor/system/ha-status`, `monitor/system/ha-checksums` |
| Rete → VPN | `monitor/vpn/ipsec` |
| Firewall → Gruppi indirizzi | `cmdb/firewall/addrgrp` |
| Firewall → Gruppi servizi | `cmdb/firewall.service/group` |
| Firewall → VIP | `cmdb/firewall/vip` |
| Firewall → IP pool | `cmdb/firewall/ippool` |
| Firewall → Profili sicurezza | `cmdb/antivirus/profile`, `cmdb/ips/sensor`, `cmdb/webfilter/profile`, `cmdb/application/list` |
| Sicurezza → Admin | `cmdb/system/admin` |
| Sicurezza → Utenti bannati | `monitor/user/banned` |
| Sicurezza → Revisioni config | `monitor/system/config-revision` |
| Sicurezza → Certificati | `monitor/system/available-certificates` |

Only `monitor/virtual-wan/health-check` and the `log/*` paths above are confirmed.

### Frontend gotchas found the hard way

- **`changeLanguage()` replaces `innerHTML` wholesale.** A Font Awesome icon on a
  translated element must live *inside* the i18n string value, not in the markup, or it
  disappears on language switch.
- **`.btn` is `width: 100%`.** Buttons outside a `.subtab-bar` need an explicit
  `style="width:auto;"` or they claim a whole row.
- **No JS test runner exists.** The frontend is checked grep-style through
  `frontend_source()` in `tests/test_helpers_frontend.py`. Logic that needs a real test
  belongs in Python — which is why the policy/stats join and the log subtype/date handling
  live in the service layer rather than the renderer.

## Skipped, and when to add it

- **Write operations** (policy enable/disable, session clear, object CRUD) — read-only was
  the explicit decision. Add when someone actually needs to change config from
  SentinelNet rather than read it; it needs a cmdb write path, an audit trail and a
  security review that none of this does.
- **Auto-refresh / polling** on the Overview counters. Manual reload button first. Add a
  timer when someone asks to watch a number move.
- **Caching of cmdb reads.** Every view fetches on demand. Add if a real box proves slow.
- **Splitting `fortigate-management.js`.** It lands around 1400 lines, inside house norms
  (`topology.js` is 2736). Split by sub-tab if it passes ~2000.
