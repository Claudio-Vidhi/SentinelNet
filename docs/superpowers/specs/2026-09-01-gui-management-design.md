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

## Audit findings

What follows was found by reading the code rather than by asking what would be
nice. Each row is a capability the data model or the API already supports and
the UI does not reach, so the cost is a control and a handler, not a feature.

| # | Gap | Evidence |
|---|---|---|
| A | A site cannot be renamed, and its subnets cannot be corrected, after creation | `update_site` accepts `name` and `subnets`; `renderSitesTable` prints both as text (`static/js/settings.js`) |
| B | A bastion's address cannot be changed after creation | `jump_host` occurs once in `static/js/settings.js`, in the creation form |
| C | A site's mode cannot be changed | `update_site` validates and applies `mode`; no control offers it |
| D | The agent's syslog listener cannot be turned off | `syslog_enabled` occurs **zero** times across all of `static/js/` |
| E | The agent never reports which code it runs | no version, commit or branch in the heartbeat payload (`services/site_agent.py`) |
| F | Neither the central nor an agent can show its log | no endpoint serves `error_log.txt` or the journal; `_agent_*` RPC verbs are update, restart, get/save inventory, config |
| G | TLS is configurable from the GUI but unusable there | see the review below — this one is not a missing control |

Gaps A-D are Phase 2. E and F are Phase 1. G is the subject of the review.

## Review: the restart gap is the real blocker

An audit pass after the phases were drafted found something that changes their
emphasis, and corrects advice given earlier the same day.

**TLS is already editable from the GUI.** `ssl_certfile` and `ssl_keyfile` are
in the advanced application settings — `_APP_ADV_ENV` in `routers/settings.py`
and the field list in `static/js/settings.js` — alongside the HTTP port, CORS
origins, the public base URL and the observability retention windows. The
operator was walked through editing `/etc/sentinelnet.env` by hand today; the
dashboard could have written the same two values.

It would not have helped, and the reason generalises:

1. **Environment variables win.** `_app_adv` is consulted only when the
   matching variable is unset (`core/data_config.py`). Once
   `SENTINELNET_SSL_CERTFILE` is exported by the unit file, the GUI field is
   dead input — it saves, it displays, and it changes nothing. Nothing in the
   UI says which of the two is in force for a given key.
2. **They need a restart, and there is no restart.** The UI is honest about it
   — *"Le modifiche richiedono il riavvio dell'applicazione"* — but the only
   way to perform that restart is a shell on the box. So every setting in that
   panel is, in practice, a shell-assisted setting.

So the largest GUI-management gap is not a missing form. It is that **a whole
category of existing settings is already exposed and cannot be applied**, and
that the app cannot say whether what is displayed is what is running.

Three consequences for the plan:

- **Item 11 (central restart) is promoted.** It was the last item of Phase 3
  because it is the riskiest; it is also the one that makes an entire existing
  settings panel work. The restart half is separable from the update half and
  much simpler: restarting a service is not the same as changing its code, so
  it can ship first, with the same external-unit mechanism and none of the
  fetch/checkout/rollback machinery.
- **Add: show which source is in force per setting.** Beside each advanced
  setting, state whether the value comes from the environment or from
  `app_settings.json`, and mark the environment ones read-only. This is small,
  and without it the panel actively misleads.
- **Add: a "generate self-signed certificate" action** for an agent or lab
  central. Today it is an `openssl req` incantation with a
  `subjectAltName` that must carry the IP, or clients reject it — exactly the
  kind of thing that belongs behind a button and not in a runbook.

The revised ordering is therefore Phase 1 unchanged, then **restart plus
setting-source display** ahead of the rest of Phase 2, because they unlock
settings that already exist rather than adding new ones.

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

### Phase 1b — Make the settings that already exist usable

Promoted out of Phase 3 by the review above: these unlock an existing panel
rather than adding new surface, and the restart half carries none of the
update path's risk.

3b. **Restart the central from the GUI.** The same external-unit mechanism as
    item 11 — `systemctl start --no-block sentinelnet-restart` through one
    exact sudoers rule — but restart only: no fetch, no checkout, no code
    change, so no rollback machinery is needed. Every advanced setting that
    says "requires a restart" becomes reachable.
3c. **Show which source is in force for each advanced setting.** Environment
    or `app_settings.json`, per key, with the environment-backed ones marked
    read-only. Without this the panel accepts values it will never apply.
3d. **Generate a self-signed certificate** for a lab or agent host, with the
    `subjectAltName` carrying the address clients will use — the detail whose
    omission makes a hand-rolled certificate fail verification.

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
