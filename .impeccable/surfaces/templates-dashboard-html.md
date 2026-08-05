---
version: 1
slug: "templates-dashboard-html"
primary_target: "templates/dashboard.html"
related_targets: ["static/css/dashboard.css"]
---

# Console shell + Operations home

**Scope.** The single-page dashboard shell (`templates/dashboard.html`) and its
landing tab `#tab-home`. The shell's component layer is shared by all 21 tabs,
so decisions here are system-wide; the composition below is home's alone.

**Visitor mode.** Operate.

**Audience and job.** Network engineers on their own estate or on several
customer estates. The job on this surface is triage orientation: which bays are
energised, what changed, and where to look next — not analysis, which lives in
the tabs this one points at.

**Task.** Answer "is anything wrong, and where" inside one viewport, then hand
off. Every element is either an index into the estate or a chronological record.

**Action.** Open the inventory (primary, the single ink block in the title row)
or start a global triage (secondary). Bays and event rows are themselves
navigation into the device tab.

**Content on hand.** `globalDevices` + `globalVersions` from `/api/local-devices`
(tenant, IP, hostname, scan status) and `/api/observability/anomalies?limit=5`.
No synthetic content: an empty inventory renders an explicit empty state saying
the diagram is drawn at first provisioning.

**Constraints.**
- Four first-class scenes: desk mid-incident, unhurried sweep, phone at the rack,
  NOC wall at distance. The wall scene is why state is carried by symbol
  geometry rather than colour alone.
- Both renditions required; neither is the default.
- Admin-gated blocks (`event strip`, `recent anomalies`) must stay behind
  `.requires-admin`; the server enforces independently.
- Every string needs an `it` and an `en` entry.

**Chosen direction.** Mimic Panel — the substation one-line and its SCADA
successor. Assigned by roll (seed `8c37ee38`, candidate 7), confirmed by the user
over three challengers and the category standard.

**Memorable moment.** The bus bar with a bay per tenant hanging off it, each bay
carrying an isolator whose *shape* is its state, and a legend directly beneath
that draws those same four shapes as a contract. On tab entry the isolators run
a staggered lamp test — the one authored motion, suppressed under
`prefers-reduced-motion`.

**Unresolved.**
- The five `.kpi-grid` strips on other tabs (fortigate, flows, provisioning,
  categories, settings) still read as stat rows rather than instruments; the
  home surface no longer uses one.
- No screenshot verification was possible in this environment; the build is
  verified by tests, type check and numeric contrast only.
- Whether the one-line should become the estate's primary navigation across
  tabs, rather than home's alone.
