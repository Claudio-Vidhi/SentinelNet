# Network segments (IT/OT) on the maps

Approved 2026-11-03 from an interactive preview with synthetic data.

## Problem

One building often holds two networks: the managed IT network (dual core,
access switches, APs) and one or more OT networks (industrial switches)
behind dedicated firewalls. The Schema ladder puts everything in one column,
so the OT ring, the OT firewalls and the IT access switches tangle.

"Zone" already means *site/location* in `topology.js` (`topoZone`,
`assignZones`). The new concept is a **segment**: a set of devices of one
tenant that form a separate network inside a site.

## Model (server-side, per tenant)

SQLite, next to `locations`:

- `segments(id, org, name, color, subnets, members, excluded)`
  - `subnets`: CIDRs; a map node whose address falls in one joins the segment.
  - `members`: node ids added by hand; `excluded`: node ids taken out by hand
    although a subnet matches.
  - One node belongs to at most one segment: saving a segment removes its
    members from the tenant's other segments.
  - `color`: one of a fixed palette (`amber teal violet rose lime sky`).
- `segment_links(org, a, b, decision)` with `a < b`, decision
  `allowed | gateway`. No row = "to verify".

API (`routers/segments.py`), tenant-scoped with `assert_group_allowed`:

- `GET /api/segments?org=` → `{segments, links}` (map tabs)
- `POST /api/segments` save (create/update), `POST /api/segments/delete`,
  `POST /api/segments/link` (decision, `null` clears) — operator and above.

## Client logic (topology.js)

- Membership: subnets ∪ members − excluded. Cores (the ladder pair) never
  join a segment.
- Gateways of a segment: its firewalls that have a neighbour outside it; if
  none, every member with a neighbour outside. A link decided `gateway` adds
  its outside end as an extra gateway.
- Finding: a link between two segments (or segment ↔ main network) whose
  segment-side end is not a gateway — a possible firewall bypass. The user
  classifies it: to verify / allowed / make gateway.
- Proposal ("detect"): firewalls removed from the graph, each component that
  no longer reaches the cores is proposed as a segment, with the /24s of its
  members as CIDRs. Confirmed with one click; never saved silently.

## Views

1. **Schema · ladder**: main network ladder on the left, one column per
   segment on the right, gateways at the column top; only core → gateway
   cables cross the border. Findings drawn as orange dashed lines.
2. **Schema · rows** and **Hierarchy**: a tinted rectangle behind each
   segment's members, label top-left. Findings as orange dashed edges.
3. **Segment editor** (modal via `openModal`): name, colour, CIDRs, device
   checklist + click-to-pick on the map, live dashed preview with the rest
   of the map dimmed, save/cancel.
4. **Findings panel** in the map side panel, one row per finding with the
   three decisions.

## Phases

1. Backend: tables, `services/segment_manager.py`, router, tests (manager +
   API with scope/role checks).
2. Client model: load segments with the map, membership, gateways,
   findings, proposal; unit test in `tests/js`.
3. Ladder columns per segment (`schemaLadderPlan`, `ladderPositions`,
   `drawLadderCables`).
4. Areas in rows + hierarchy, editor modal with preview.
5. Findings panel, i18n (`tr`), a11y, screenshots, CHANGELOG.
