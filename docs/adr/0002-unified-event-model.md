# ADR-0002 — Every source is projected into a single `events` table

**Status:** Accepted
**Date:** 2026-07-27

## Context

Sources arrive in incompatible shapes: per-minute flow buckets, syslog lines
with vendor-specific bodies, REST snapshots, SNMP walks. The first correlator
read `syslog_events` directly and knew about FortiGate `key=value` bodies. Each
new source meant touching correlation logic, and each consumer (correlator,
baseline, timeline, AI context) re-derived the same fields with slightly
different code.

## Decision

Each source keeps its own ingestion format and raw table. An **adapter** in
[normalize.py](../../observability/normalize.py) projects it into a single
`events` table with one shared vocabulary: `flow.aggregate`, `log.security`,
`device.state`, `interface.change`, `platform.exporter_unknown`, and so on.

Everything downstream — rules, evidence, incidents, baseline, timeline —
reads `events` and only `events`.

Progress is tracked per source in `normalize_cursors`; re-entry is idempotent
because `dedup_key` is `UNIQUE`, so a rewound cursor rewrites the same rows
rather than duplicating them.

## Consequences

- A new source costs a decoder plus an adapter. Nothing downstream changes.
- The correlator no longer knows what a syslog line is. That's the point.
- Platform diagnostics ride the same rails: an exporter outside inventory
  becomes `platform.exporter_unknown` on the reserved `__platform__` tenant, and
  inherits rules, evidence, incidents and timeline instead of needing a parallel
  path for internal telemetry.
- Cost: storage duplication. Events are a projection of rows that already exist.
  Mitigated by giving `events` the same retention as the longest-lived source it
  projects (flows, 30 days), so no event outlives its origin.
- Cost: one more hop between observation and conclusion. Adapter bugs show up as
  missing conclusions, which is harder to spot than a crash.

## Alternatives rejected

**Correlate directly over the raw tables.** What existed before. It couples
every rule to every source format and makes multi-source correlation — the whole
point of the platform — a join problem that grows quadratically with sources.

**A common schema at ingestion time** (decoders write `events` directly).
Rejected: it would mean the raw tables lose fields that only matter to their own
tab (Flow SIEM needs the full syslog body), and a decoder change would then
require a schema migration.

## When to revisit

If the storage cost of the projection becomes the dominant term, or if a source
appears whose facts genuinely don't fit the vocabulary. In the second case the
answer is to extend the vocabulary, not to bypass the table.
