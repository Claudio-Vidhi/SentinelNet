# ADR-0003 — Rules produce evidence with a causal role; the incident is a derived view

**Status:** Accepted
**Date:** 2026-07-27

## Context

The original correlator produced `correlated_events` directly: a rule fired, an
incident existed. That made the conclusion an assertion. When an engineer asked
"why does it say this?", the answer was the rule's name and nothing else — no
way to show what corroborated it, no way to express that one fact triggered
while another merely supported.

The engineering principles
([principles.md](../principles.md)) require
every automated conclusion to expose supporting evidence, a confidence score and
a reasoning path.

## Decision

Rules produce **evidence**, not incidents. Each piece of evidence carries:

- a **causal role** *declared by the rule*, never inferred: `trigger`,
  `supporting`, `symptom`, `consequence`;
- **provenance**: `rule_id`, `rule_version`, and the thresholds actually used.

The **incident** is a derived view ([incidents.py](../../observability/incidents.py)):
evidence about the same entity within a time gap is grouped; the cause is the
rule behind the `trigger` evidence; every distinct form of corroboration adds a
confidence step, each one published in `reasoning_json.sources_used`.

**Retraction** is likewise produced by a rule, never by an adapter. The fact
that justifies it (the `witness`) is stored as evidence in its own right, so
`retracted_by_evidence_id` points at something readable — and the retraction is
itself retractable.

## Consequences

- Conclusions are reconstructable. "Confidence 76%" has the increments that
  produced it recorded next to it.
- The roles earn their keep: other evidence doesn't compete for the cause, it
  reinforces it. That's a different data model from "N alarms, pick the loudest".
- One evidence set feeds the incident engine, the baseline, the AI assistant and
  the knowledge base without duplicating correlation logic.
- Cost: two engines instead of one, with the grouping heuristic (`GAP_S`,
  `QUIET_S`) as a tuning surface that can group too eagerly or not enough.
- Cost, and a real one: **retraction happens after concluding.** Fine while only
  the UI reads conclusions. With a notification engine, "I concluded, then
  retracted" means someone was already woken at 3am, and you can't unsend an
  email. The fix is a per-rule "how many observations before concluding", still
  outstanding ([roadmap.md](../roadmap.md) §3).

## Alternatives rejected

**Nagios-style HARD/SOFT states.** Rejected as a complete model — evidence with
causal roles and confidence says more than OK/WARNING/CRITICAL. But the part it
solves (don't conclude on the first observation) is genuinely missing here, and
the answer is a rule parameter, not a state machine.

**Rules writing incidents directly, with a "related events" list.** Cheaper, and
it's what the first version did. It cannot express *why* a related event is
related, which is exactly the question being asked.

## When to revisit

When notifications ship. At that point the "confirm before concluding" gap stops
being cosmetic and this ADR needs a companion.
