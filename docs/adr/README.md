# Architecture Decision Records

One decision per file. Short: context, decision, consequences, and what would
make us revisit it. If it fits in a module docstring and touches only that
module, it isn't an ADR — it stays in the docstring.

Never edit a past decision to make it look right. If a decision is reversed, add
a new ADR that supersedes it and mark the old one.

| # | Decision | Status |
|---|---|---|
| [0001](0001-python-rules-not-yaml.md) | Correlation rules are Python callables, not a YAML DSL | Accepted |
| [0002](0002-unified-event-model.md) | Every source is projected into a single `events` table | Accepted |
| [0003](0003-evidence-and-derived-incident.md) | Rules produce evidence with a causal role; the incident is a derived view | Accepted |
| [0004](0004-single-process-sqlite-writer.md) | SQLite with one writer thread, single process | Accepted |
| [0005](0005-strict-tenant-attribution.md) | Unattributable records are dropped, never given a fallback tenant | Accepted |
| [0006](0006-deterministic-correlation.md) | Correlation is deterministic; the AI narrates, it doesn't decide | Accepted |
| [0007](0007-numeric-snmp-oids.md) | SNMP uses numeric OIDs, no MIB resolution | Accepted |
| [0008](0008-agent-rest-relay.md) | The site agent relays read-only REST calls, restricted by an allowlist checked at both ends | Accepted |

## Template

```markdown
# ADR-XXXX — Title

**Status:** Accepted | Superseded by ADR-YYYY
**Date:** YYYY-MM-DD

## Context
What was true when the decision was made.

## Decision
What was decided. Present tense, no hedging.

## Consequences
What this costs and what it buys — including the parts that hurt.

## Alternatives rejected
What else was on the table and why it lost.

## When to revisit
The concrete signal that would make this decision wrong.
```
