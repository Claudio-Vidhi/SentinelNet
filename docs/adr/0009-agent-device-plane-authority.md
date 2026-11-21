# ADR-0009 — The probe agent is the authority for what it does to its devices; central only asks

**Status:** Proposed
**Date:** 2026-11-21

## Context

Agent mode (Mode B) promises one security property above the others: device
credentials stay inside the site, so a compromised central server cannot take
them ([probes.md](../probes.md), principle 2). ADR-0008 kept that promise for
the REST relay by having the agent re-check the read-only allowlist itself:
*the agent trusts central for scheduling, not for authorisation*.

Every other channel from central to the agent still works the other way
round. Today central can, on its own authority:

- **Widen what a CLI job may do.** The blacklist bypass is decided at central
  and travels with the job; the agent honours it. A job can therefore change
  device configuration on any device the agent knows.
- **Decide where a credential is presented.** Central adds and updates device
  records on the agent (the heartbeat device push, the inventory-save RPC).
  A record that comes from central can name any address and still resolve to
  a credential the agent holds locally (the site default, a tenant identity).
  Choosing the address a credential is sent to is the same thing as reading
  the credential.
- **Rewrite the agent's own configuration.** The config RPC merges whatever
  keys it receives and persists them, not only the intervals and syslog
  settings the UI exposes.

Each of these grew for a good reason. Together they mean the authenticated
agent and whoever controls central share one authority boundary:
compromise central and you get device write access, and the locally held
credentials too, at every agent site. That is the problem [roadmap.md](../roadmap.md) §2
describes. Its trigger was "the allowlist growing to cover writes". It has
not grown, but writes already reach devices through the CLI path. So this
decision cannot wait for it.

`central_manages_devices` is the one opt-in case where the credentials do
live on central. There a compromised central has them anyway. What it must
still not get is the *locally* held ones, nor write access to devices the
site never agreed to expose.

## Decision

The agent holds the authority over device actions and over itself. Central
sends **requests**; the agent checks each one against a **local policy** that
central cannot write, and refuses what the policy does not grant.

1. **Local device policy.** The agent reads a policy file from its own data
   directory, editable only on the agent host. No RPC, heartbeat field or
   pushed record writes to it. It declares:
   - `allowed_subnets`: the only addresses this agent will open a session to.
   - `change`: the devices, by address or by subnet, on which configuration
     changes are allowed. Empty by default.

2. **Two capability classes, checked at the agent.**
   - *observe*: read-only CLI (the blacklist with no bypass), the ADR-0008
     REST allowlist, triage/backup and the OT probe. Allowed on every device
     inside `allowed_subnets`.
   - *change*: a CLI job that carries a blacklist bypass, and any future REST
     write. Executed only when the local policy grants `change` for that
     device. Central's bypass flag remains an input. It is a request, and
     the audit line at central still records who asked.

3. **Credentials are bound to addresses, not to records.** A locally held
   credential (per-device, tenant identity, site default) is presented only to
   an address inside `allowed_subnets`. A device record that originates from
   central uses only the credentials that record itself carries. It never
   falls back to the site default or to a local identity.

4. **The config RPC has a key allowlist.** Central may set what the UI already
   offers: intervals, syslog port and listener state. It may never set the
   central URL, the token, the probe id, the data directory or the policy
   path. Unknown keys are refused, not merged.

5. **The agent keeps its own record.** Every device job is appended to a local
   log with its kind, target, requester, the policy verdict and the outcome.
   Someone at the site can see what central asked for without trusting
   central's audit log.

6. **The agent declares its policy upward.** The heartbeat reports the policy
   version and, per device, whether `change` is granted. Central uses this to
   explain a refusal before queuing a job that would be refused. This is a
   convenience only. The agent's check is the boundary.

## Consequences

- A compromised central loses device write access at agent sites. It also
  loses the ability to steer locally held credentials. With the defaults it
  can still read device state, which is what monitoring requires.
- **Behaviour change on upgrade.** A site that today pushes configuration
  through agent CLI jobs stops being able to until someone on site grants
  `change`. Making that a deliberate local act is the purpose of this
  decision. It needs a release note and a version bump.
- **No policy file yet** (an upgraded agent nobody has configured): `change`
  is denied and `allowed_subnets` falls back to the addresses already in the
  local inventory at first start. The heartbeat reports `policy: none`, and
  central shows it per probe until the site writes a policy. This fails closed
  on writes and does not break monitoring.
- Enabling changes at a remote site needs access to the agent host. That
  access is exactly what the boundary is about, and also the friction this
  decision accepts.
- `central_manages_devices` keeps working: its records carry their own
  credentials. A pushed record whose address falls outside `allowed_subnets`
  is refused and reported, instead of being dialled.
- The allowlist logic and the policy check run on agent code. An outdated
  agent enforces the old, weaker model. The heartbeat's policy version makes
  that visible, and central can refuse `change` jobs to an agent that does
  not report a policy.
- Not addressed: the self-update RPC pulls code from the remote configured on
  the agent, and central only triggers it. The code's integrity is the
  repository's problem, not this boundary's. Point 4 keeps that remote out of
  central's reach.

## Alternatives rejected

**Keep authority at central, rely on RBAC and the audit log.** This is the
status quo. RBAC protects central from its own users, not the sites from
central. An audit log kept by the compromised party is not evidence.

**Operator-signed jobs.** Central becomes a dumb relay, and each `change` job
carries a signature from an operator key that the agent verifies. This is
the strongest model, and the natural next step. But it needs per-user key
enrolment at every agent, rotation, and signing in the browser. All of that
protects an action the local policy already lets each site switch off. Worth
building once `change` is granted widely, not before.

**Short-lived device-plane tokens issued by central** (the credential
ADR-0008 declined). Central issues them, so a compromised central issues them
to itself. It adds a rotation story and still leaves central as the
authority.

**Remove device writes from agent mode entirely.** This is the simplest
option, and the policy's default already behaves this way. Keeping `change`
as a local opt-in covers remote remediation at sites where one team owns both
ends, without making it the default.

## When to revisit

- When `change` is granted at most sites: the local policy has become a
  formality, and operator-signed jobs are the next boundary.
- If a second channel from central to agent appears (a new job kind, a new
  RPC, a new heartbeat field that writes local state). It must declare its
  capability class here before it ships, or this decision has a hole.
