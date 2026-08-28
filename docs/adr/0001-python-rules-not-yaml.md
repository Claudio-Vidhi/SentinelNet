# ADR-0001 — Correlation rules are Python callables, not a YAML DSL

**Status:** Accepted
**Date:** 2026-07-27

## Context

The correlation engine needs a rule catalog: "syslog severity ≤ 3 with a
corroborating flow → evidence". The obvious industry pattern is a declarative
rule file (YAML/JSON) interpreted at runtime, on the argument that it lets
non-developers write rules and change them without a release.

The codebase already had a precedent pointing the other way:
`services/netsec_audit/benchmarks.py` had used Python callables in a table for
its security benchmarks, and that had worked well.

## Decision

Rules are **Python callables in a table** ([rules.py](../../observability/rules.py)).
Each declares its `rule_id`, `rule_version`, the causal role of the evidence it
produces, and its tunable parameters with defaults.

**Thresholds** are runtime-configurable through `app_settings`
(`correlation_rules` section). **Logic** is not. The thresholds actually applied
are written into `evidence.params_json` next to `rule_version`.

## Consequences

- Debuggable: a breakpoint inside a rule shows exactly why it fired. No
  interpreter to reason through.
- Full language available: `or`, early returns, helper calls, real data
  structures.
- Provenance is exact. Since the effective parameters travel with the evidence,
  two different outcomes from the same rule are always distinguishable — without
  it they would share a provenance and be unexplainable six months later.
- Cost: a new rule requires a release. Accepted — the operators of this tool are
  the same people who build it.
- Cost: a malformed rule is a Python error at import time, not a validation
  message. Acceptable, and caught by the test suite.

## Alternatives rejected

**YAML DSL with a condition interpreter.** Looks more flexible right up to the
first `or`. From there you're writing a worse language inside Python, and every
feature request becomes an interpreter feature. The apparent benefit —
non-developers authoring rules — doesn't apply here.

**Full plugin architecture.** The equivalent already exists twice: a new source
is an adapter in `normalize.py`, new logic is an entry in `RULES`. A third
mechanism would only give three places to look
(see [roadmap.md](../roadmap.md)).

## When to revisit

If rules ever need to be authored by people who don't have the repository and
can't ship a build. At that point the answer is probably a constrained rule
*builder* on top of the same callables, not an interpreter underneath them.
