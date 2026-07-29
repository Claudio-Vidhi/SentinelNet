# ADR-0005 — Unattributable records are dropped, never given a fallback tenant

**Status:** Accepted
**Date:** 2026-07-27

## Context

Every row in observability carries a `tenant`, and RBAC scoping filters on it: a
user restricted to one site must see only that site. UDP ingest has no
authentication and no tenant field — the only attribution signal is the source
IP of the datagram, resolved against the inventory.

The first implementation wrote `tenant = "default"` for anything it couldn't
resolve. The result: rows visible to nobody in particular, polluting every
aggregate, and no way to tell "site with no traffic" from "site whose exporter
isn't registered".

## Decision

Resolve the datagram's source IP against the inventory. If it doesn't resolve —
unknown exporter, or a collision between two devices with the same IP — the
records are **dropped**. Specifically:

- upsert into `quarantined_exporters`;
- one audit entry, rate-limited to 1/hour per exporter;
- `dropped_unknown_exporter` metric;
- the quarantine row is projected into `platform.exporter_unknown` on the
  reserved `__platform__` tenant, which raises `FLOW_EXPORTER_UNKNOWN_001`.

**No record is ever written with a fallback tenant.**

## Consequences

- Data without a trustworthy site is worse than no data: it poisons scoping for
  every other tenant. Dropping it is the conservative choice.
- The loss is not silent. It becomes evidence on the platform tenant, visible to
  whoever administers the platform (`user_group_scope` returns `None` for them),
  and the operator sees "your exporter isn't registered" instead of an empty tab.
- `__platform__` is visible only to unrestricted users. That falls out of the
  scoping rule rather than needing a special case.
- Cost: configure export on a device before registering it in inventory, and you
  lose that data. This is the single most common cause of "the Live Flows tab is
  empty" ([operations.md](../operations.md) §4).
- **Known limitation:** attribution by source IP breaks for exporters behind
  NAT. The answer is a site relay, not opening UDP over the VPN.

## Alternatives rejected

**`tenant = "default"` for unresolved records.** What existed. Produces rows
that belong to nobody and are counted by everybody's aggregates.

**Buffer unattributed records and re-attribute when the device is registered.**
Attractive, but it means unbounded retention of unattributable data plus a
re-attribution job — and the operator still has to register the device, which is
the action the drop already prompts.

**Accept the exporter and infer the tenant from the subnet.** Guessing. Same
class of error as the synthetic VLAN, without the ability to mark it as guessed.

## When to revisit

If NAT'd exporters become common enough that the site relay isn't a sufficient
answer. Then the attribution signal needs to move out of the IP header —
per-exporter shared secret, or attribution at the relay — not become a heuristic.
