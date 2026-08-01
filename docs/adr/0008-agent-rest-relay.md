# ADR-0008 — The site agent relays read-only REST calls, restricted by an allowlist checked at both ends

**Status:** Accepted
**Date:** 2026-08-01

## Context

In agent mode (Mode B) central never reaches the site's devices: the agent
connects outbound over HTTPS and pulls work from a job queue. Until now that
queue carried **one thing** — a CLI command string — which `run_jobs` executed
over local SSH.

That was enough while the relay's only job was "run a show command". It stopped
being enough with the client diagnosis, which asks questions that have no
reliable CLI equivalent:

- `monitor/firewall/policy-lookup` — *which policy would match this flow?*
  `fortigate_service.policy_lookup` says outright that no 1:1 CLI equivalent
  exists.
- `monitor/vpn/ipsec` — *is the tunnel to the other site up?*
- `monitor/router/ipv4` — *is there even a route to that subnet?* Parsing the
  CLI text for this varies by version, and a parser that guesses wrong sends an
  engineer hunting a routing fault that isn't there.

Without a REST path, every branch and remote site answers "unavailable" to
exactly the questions the feature exists to answer. With an *unrestricted* REST
path, a site token becomes arbitrary API access to every device in the site —
including `cmdb/` writes — and the separation between the agent control plane
and the device data plane ([roadmap.md](../roadmap.md) §2) disappears.

## Decision

`command_jobs` gains a `kind` column (`cli` | `rest`; existing rows and older
agents default to `cli`). For `kind='rest'` the `command` column holds
`{"path": ..., "params": {...}}` and the path must match
`site_manager.REST_RELAY_ALLOWLIST`.

The allowlist is **read-only by construction**: only `monitor/` and `log/`
paths. Never `cmdb/` (which writes configuration), never
`monitor/system/config-script/upload`.

`rest_path_allowed()` is enforced **twice**:

1. by central, in `enqueue_job()` — so *every* caller passes the gate rather
   than each endpoint remembering to check;
2. by the agent, in `_execute_rest_job()`, before touching the device.

The second check is not redundant. The stated security property of Mode B is
that device credentials stay inside the site *even if central is compromised*.
An agent that executes whatever path central dictates gives that property away.
The agent trusts central for **scheduling**, not for **authorisation**.

## Consequences

- Remote-site clients become diagnosable: policy lookup, sessions, routes and
  tunnel state work at branch sites, not just at `central`.
- Widening the relay is now a deliberate act: adding a path means editing one
  named constant, in one file, next to the comment explaining why the list is
  short. It cannot happen by accident in a caller.
- The agent must be upgraded to serve `rest` jobs. An older agent receives the
  job, doesn't recognise `kind`, and falls through to the CLI branch — where it
  tries to run the JSON as a command and returns an error. Ugly but contained,
  and the job is marked `error` rather than silently lost.
- Cost: two copies of the allowlist logic must stay in step. They share one
  function in `site_manager`, so the agent and central cannot drift — but an
  agent running old code carries an old list. That is the intended direction of
  failure: an outdated agent permits *less*, never more.
- The relay still cannot write. Anything that changes device configuration goes
  on as it did before: a CLI job, subject to the command blacklist and RBAC.

## Alternatives rejected

**Leave it unavailable and say so.** The honest minimum, and what the first
draft did: the firewall section would report "agent site: REST not reachable".
Correct, but it makes the feature useless at exactly the sites that need it
most — a branch is where you cannot walk to the rack.

**Relay arbitrary REST calls, rely on RBAC at central.** Collapses the two
planes into one. Whoever holds a site token, or whoever compromises central,
gets the device API. The credential isolation that justifies Mode B in the first
place would be decorative.

**Translate each REST need into a CLI equivalent.** Works for sessions and
logs, and not at all for `policy-lookup`, which is the single most valuable
answer in the whole diagnosis. Half the feature, plus a text parser per FortiOS
version.

**Give the agent its own outbound REST proxy with a separate credential.**
Cleaner in principle — a genuine second principal — but it is a new identity, a
new rotation story and a new failure mode, to solve a problem an eight-entry
allowlist already solves.

## When to revisit

If the allowlist starts growing to cover write operations, or if a second
consumer wants the relay for something other than diagnosis. At that point the
right move is the separate device-plane credential this ADR declined — the
allowlist is a boundary that works because it is small, and it stops being one
as soon as it is long.
