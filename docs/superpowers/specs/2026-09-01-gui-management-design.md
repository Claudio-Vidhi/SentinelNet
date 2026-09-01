# GUI-first management: sites, agents and updates

**Date:** 2026-09-01
**Status:** proposed, not approved

## Problem

The dashboard can create a site and tune three agent timings. Everything else
about running SentinelNet needs a shell on the box: renaming a site, changing
its subnets or its bastion address, enrolling an agent, finding out which code
an agent is actually running, reading its log, updating the central.

That is not a theoretical complaint. This session lost an hour to it. The
agent's self-update button reported:

```
[git pull] code=0
Already up to date.
From https://github.com/…  c0fc7c6..b5c8a85  Dev -> origin/Dev
```

Those two lines contradict each other — git fetched new commits and the
checkout did not move — and the dashboard had no way to say which branch the
agent was on, which commit it was running, or whether the restart had changed
anything. Answering it took SSH, `git branch --show-current` and `git log`.

The goal is not "more buttons". It is that an operator can answer *what is
deployed where, and is it what I think it is* without leaving the browser, and
can change a site's configuration without hand-editing JSON on a VM.

## Improvements on what was already suggested

Four features were proposed earlier today. Each has a defect worth fixing
before it gets built.

**The update-available indicator** was scoped as "compare `__version__` to the
newest tag". That answers the wrong question. The operator's real question is
never "is there a newer release" in the abstract — it is "are my central and my
agents all running the same thing, and is that thing current". So it should be
a **fleet version panel**: installed version and commit for the central and for
every agent, beside the newest available tag, with anything lagging marked. The
single-version indicator is a strict subset of that and costs the same.

**The agent self-update** returns the raw `git pull` output and nothing else.
It should report the resulting version and commit, so "did it work" is answered
by a value rather than by prose the operator has to interpret. It should also
run `uv sync` — a release that adds a dependency currently leaves the agent
unable to restart — and update to a **tag**, not to whatever sits at a branch
head.

**The central self-update** was designed as tag + external updater + rollback.
That is right, and the ordering matters more than it first appeared: rollback
cannot live inside the process that exits, so the external updater is a
prerequisite for the rollback rather than an independent nicety.

**The per-user data directory for the frozen build** was framed as an installer
prerequisite. It is also a live bug: `DATA_DIR` is CWD-relative
(`core/data_config.py`) with no `chdir` anywhere in the tree, so the same exe
launched from a different folder silently opens a different, empty install. It
deserves fixing on its own merits, whether or not an installer is ever built.

## Phases

Ordered so each phase is useful alone and lowers the risk of the next. Phase 1
carries no risk at all and would have prevented today's confusion.

### Phase 1 — Know what is deployed

No new authority, nothing that can break a running system. Read-only.

1. **The agent reports its identity on the heartbeat.** Version, git commit,
   branch, and whether its checkout is dirty; stored on the site record and
   shown in the site row and the agent panel. The highest-value item in this
   document: it is exactly what today's failure needed and did not have.
2. **Fleet version panel.** Central and every agent, installed vs available,
   with anything lagging or mismatched marked. Needs three-way install-kind
   detection (`exe` / `git` / `source`) — `sys.frozen` for the first, a `.git`
   directory for the second; the third matters because a source download can no
   more `git pull` than an exe can.
3. **Agent log tail.** An `_agent_logs` RPC returning the last N lines of the
   agent's journal, rendered in the agent panel. Read-only, and it removes the
   most common reason to SSH into a site.

### Phase 2 — Configure a site completely

Every field the data model already supports should be editable where the site
lives, not only at creation.

4. **Edit name and subnets after creation.** `update_site` already accepts
   both; there is no UI, and the table renders them as plain text.
5. **Edit the bastion host and port after creation.** `jump_host` appears in
   the creation form only, so a bastion that changes address today means an API
   call by hand.
6. **Change a site's mode**, with guard rails: moving to `central` drops the
   token, to `agent` mints one, to `jump` requires the bastion fields.
   `update_site` supports it; the UI does not offer it.
7. **The agent config panel gains its missing keys**: the syslog listener
   on/off (the port is settable but the listener cannot be disabled), and the
   resolved data directory shown read-only, so an operator can see where the
   agent actually writes.
8. **Agent enrollment helper.** On creating an agent site, generate the exact
   `agent.json` and the install commands with the token filled in, ready to
   paste. The token is shown once; this makes that one moment useful instead of
   handing over a bare string.

### Phase 3 — Update safely, from the browser

9. **Frozen build data directory.** Default to a per-user location when
   `sys.frozen`, migrate by *copying* from the old CWD location on first run,
   and show the resolved path in Settings.
10. **Agent update, hardened.** Update to a chosen tag rather than a branch
    head; run `uv sync`; report the resulting version and commit; verify the
    agent comes back by waiting for its next heartbeat, and say so plainly when
    it does not.
11. **Central update.** A `sentinelnet-update.service` oneshot that fetches,
    checks out the tag, runs `uv sync` and restarts the service, triggered from
    the app with `systemctl start --no-block` through one narrow sudoers rule.
    The app never kills itself mid-write; on failure the updater fails and the
    old version is still running and still reachable. Records the previous
    commit and rolls back if the new one does not answer `/api/version` within
    a timeout.

### Phase 4 — Installer (decide later)

Worth starting only once item 9 has shipped and the data directory no longer
lives inside the program directory. Nothing in phases 1-3 depends on it.

## What this deliberately does not do

- **No arbitrary command execution from the GUI.** The update path resolves to
  a tagged release, never to "run this string". The central holds every site's
  credentials; a general remote-shell button on it is worse than the
  convenience is worth.
- **No automatic updates.** Every phase 3 action is operator-initiated. An
  unattended update of the box holding the credentials for every managed
  network is not a feature.
- **No editing of another site's devices from an agent panel.** The per-site
  isolation the relay endpoints enforce must not be undone by a management
  screen.

## Risks

- **Update from the GUI is remote code execution by construction.** Pinning to
  tags shrinks who can trigger it from "anyone who can push" to "anyone who can
  cut a release". Signed tags shrink it further and are the natural next step,
  not a blocker.
- **The agent identity report reveals the branch and commit of a
  customer-site machine to the central.** Information the central's operator is
  entitled to, but it belongs in the site record, not in anything
  world-readable.
- **Item 11 needs a sudoers rule.** It must name one exact command, not a
  wildcard: the difference between "may start one unit" and "may run systemctl"
  is the difference between a feature and a privilege escalation.
