# ADR-0006 — Correlation is deterministic; the AI narrates, it doesn't decide

**Status:** Accepted
**Date:** 2026-07-27

## Context

The platform ships an LLM assistant and an MCP server. The tempting shortcut is
to hand raw telemetry to a model and let it find the anomalies — it demos well
and skips the rule catalog entirely.

The engineering principles are explicit about the opposite: correlation must be
deterministic wherever possible, no hidden logic, and every conclusion must
explain itself. "AI detected anomaly" is named as the anti-pattern.

## Decision

The correlation engine is deterministic: rules over the event model, evidence
with declared roles, incidents derived by fixed grouping. Given the same events
and the same thresholds, the same conclusion — reproducibly.

The AI reads what the engine already concluded and narrates it. Constraints on
that path:

- context is assembled **server-side**; the browser sends only identifying
  tuples, never volumes, and totals are re-derived from the database;
- tenant scope stays applied in `AND` — client-supplied keys can never widen it;
- context is always aggregated or top-N, never a raw dump;
- everything passes through one redaction choke-point
  ([security/redaction.py](../../security/redaction.py)) before leaving;
- configuration proposals are **proposals**: the model emits a fenced
  `sentinelnet-config` block, the UI shows it, and only explicit user
  confirmation routes it to `/api/bulk-command` with CLI blacklist, RBAC and
  audit unchanged.

## Consequences

- Conclusions are reproducible and auditable. A rule that fires wrongly can be
  fixed; a model that concludes wrongly can only be re-prompted.
- The engine works with no LLM provider configured at all. The AI is an
  interface, not a dependency.
- No prompt-injected fact can become an incident, because incidents don't come
  from the model.
- Cost: every detection has to be written. There's no "the model will figure it
  out" fallback for the long tail.
- Accepted by design: config and flow summaries do leave for third-party LLM
  providers. Redaction reduces the exposure; choosing which providers are
  acceptable is a user policy decision, not something the code can settle
  (gate I-1 in [CONTRIBUTING.md](../../CONTRIBUTING.md) §6).

## Alternatives rejected

**LLM-based anomaly detection over raw telemetry.** Unexplainable and
unreproducible, and it makes network conclusions depend on an external service's
availability, cost and version.

**ML anomaly detection (unsupervised) instead of a baseline.** The statistical
baseline answers the same question with an explanation attached. If the
statistics ever need to get more sophisticated, the path is a better estimator
in `baseline.py` — still emitting facts for rules to interpret, not a black box
emitting conclusions.

## When to revisit

Not on capability grounds. This would only change if explainability stopped
being a product requirement, which would be a different product.
