# Network Blueprint

The Blueprint is the **expected** network of an organization, kept next to the
**observed** one. The expected side is the organization's locations (see
[organizations-locations.md](organizations-locations.md)) plus the links between
them and each location's gateway. The observed side is what SentinelNet already
collects: inventory devices, ARP entries, routes and IPsec tunnels. Deterministic
checks compare the two and, where they can, propose the missing piece.

Open it from the «Blueprint di rete» tab (admins only) and pick the organization.
The examples below use an organization with `10.10.0.0/16`, a `milano` hub and a
`roma` branch.

## Drafts

Nothing in the Blueprint writes straight to the model. Every edit (a new
location, a subnet, a gateway, a link, a preset, an accepted proposal) becomes an
operation in the organization's **draft**. The draft bar shows «Bozza · N
modifiche · da rev M»:

- «Rivedi» lists the operations; each can be edited or removed.
- «Applica» writes them all in one transaction, with an optional note. It is
  all-or-nothing: if one operation is invalid (for example deleting a location
  that still has devices, the message gives the count) nothing is applied.
- «Scarta» throws the draft away.

If someone changed the model after the draft was started, Apply answers «Il
modello è cambiato» and shows what changed in between. «Allinea alla versione
attuale» moves the draft onto the current revision and you apply again.

## Revisions

Every write to an organization's locations or links, from any path (the
Organizations tab, a draft, a restore, the upgrade migration), appends a
revision with a full snapshot. «Storico» lists them (number, when, who, source,
note); pick two to see the diff: locations and links added, removed or changed.

The history of an organization survives the deletion of the organization.

«Ripristina questa revisione» never rewrites history. It builds a **draft** that
brings the model back to that revision; review it, apply it, and the result is a
new revision whose content equals the old one. A location deleted since then
comes back with its old id, or with a suffix if the id is taken (the restore
says so).

## Presets

«Preset…» creates a draft from a fixed skeleton. N is 1 to 50 (ignored by
Sede singola).

| Preset | Result |
|---|---|
| Sede singola | one `hq` «Sede principale», only if the organization has no locations |
| Hub-and-spoke | the existing `hq` as hub (else a new «Sede centrale», `hq`) plus N branches «Filiale k», each linked to the hub by VPN |
| Hub-and-spoke con DC | as above, plus the existing datacenter (else a new «Datacenter»), linked to the hub as `wan`; each branch is linked by VPN to both |
| Full mesh | N new locations «Sede N» (the first is the `hq` if none exists, otherwise all are branches), with every pair of locations, old and new, linked by VPN |

Existing locations are kept: a preset only adds. Branch numbering continues
after the branches already there. Subnets are left empty for you to fill in (or
to accept from the checks).

## Checks

«Verifica» runs the checks on the model with the open draft applied in memory,
so a proposal already in the draft disappears. A routing or VPN check on an existing link without the data it needs
answers **sconosciuto**, never «ok». The discovery checks (`arp_uncovered`,
`subnet_unused`, `route_without_link`, `tunnel_without_link`) only propose, so
without their data they simply produce no finding. A finding with a proposal has a checkbox and
«modifica»; «Aggiungi alla bozza» adds the selected proposals. Rejected proposals
are not remembered: they come back while their cause persists.

| Code | Compares | Sconosciuto when |
|---|---|---|
| `subnet_overlap` | subnets of two locations overlap (error) | never |
| `location_no_subnets` | location without subnets (warning) | never |
| `location_isolated` | branch/warehouse with no chain of links to an HQ or datacenter (warning) | never |
| `location_no_gateway` | location without a gateway (warning) | never |
| `gateway_not_in_location` | gateway IP is not a device of that location (error) | never |
| `device_outside_subnets` | device IP outside its location's subnets (warning) | never |
| `arp_uncovered` | /24 seen in ARP by a gateway that no location covers (warning) | no finding without ARP data |
| `subnet_unused` | declared subnet with no device and no ARP entry (info) | no finding unless the location's gateway reports ARP |
| `link_no_route` | gateway of A has no route to a subnet of B, or vice versa (error; warning via a default route, or when only backup static routes are known) | a location has no gateway, or no routes are known for it |
| `route_without_link` | route from A's gateway towards B's subnets with no link A-B (info) | no finding without routes |
| `vpn_link_down` | `vpn` link with no up tunnel between the two gateways (error) | neither side has FortiGate tunnel data (one known side decides) |
| `tunnel_without_link` | up tunnel between two gateways with no link (info) | no finding without tunnel data |

Caveats:

- **Routes** come from the latest **backup** of each gateway until you press
  «Aggiorna dai gateway», and a backup holds static routes only. Dynamic routes
  (BGP, OSPF) appear only after a live refresh, so without one `link_no_route`
  is only a warning: the route may exist in the running table.
- **Tunnels** are read from FortiGate gateways only. A `vpn` link whose gateway
  is another vendor stays **sconosciuto**.

## Aggiorna dai gateway

Live collection, per gateway: the full route table and, for FortiGates, the
IPsec tunnels. It runs from the central server on an explicit click, never in the
background. An unreachable gateway becomes a row with its error and the others
are still collected. Gateways of locations whose probe is an **agent** are not
reachable from the central server and are reported as errors. Locations without a
gateway are skipped (and raise `location_no_gateway`). The snapshot age is shown
in the top bar; one snapshot per organization, replaced by each refresh.

## Primi passi

A panel at the top, shown until complete, derived from the model and the checks
(nothing is stored). In order: locations defined, every location has subnets,
every non-HQ location is linked, every location has a gateway, gateway snapshot
collected, no error finding. Each item points to its action.

Quick start: Preset → Hub-and-spoke with N=2 → «Rivedi» → «Applica». Then fill
the subnets (`10.10.0.0/24` for `milano`, `10.10.1.0/24` for `roma`) and pick the
gateways, and run «Verifica».
