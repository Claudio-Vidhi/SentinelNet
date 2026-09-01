# Agent relay: status and triage/backup through the site agent

**Date:** 2026-09-01
**Status:** approved, not implemented

## Problem

A jump site gives the central a way to *reach* devices it has no direct route
to: every SSH session is tunnelled through the bastion, so the operator sees a
site that behaves like any other. A site agent gives the opposite guarantee —
nothing inbound, credentials stay at the site — and pays for it by leaving the
central with no way to reach anything at all.

Until commit `b9ecd63` the central papered over this by probing the devices
directly. That contradicted the mode's premise: on a routed lab it appeared as
denied ICMP and denied SSH from the central in the customer's firewall log, and
on a genuinely NAT'd site it produced devices permanently reported "offline"
because the probe never arrived. `b9ecd63` stopped the probing and reported the
"not measurable" tri-state instead — honest, but it left agent sites with no
device status at all, and made triage and backup refuse outright.

This design restores those capabilities the only way the mode allows: the agent
performs the work locally and the results travel up the connection it already
holds open.

## What exists already

The relay spine is built and in production use:

| Operation | Relayed today | Mechanism |
|---|---|---|
| CLI commands (single + bulk) | yes | job queue, `kind='cli'` |
| FortiGate/WLC REST calls | yes | job queue, `kind='rest'` |
| MAC / ARP / syslog / inventory | yes | agent pushes on its own cycle |
| Ping / reachability | **no** | — |
| Triage + backup | **no** | central SSHed directly; now refuses |

So this is an extension of a proven pattern, not a new channel. The agent runs
the full driver stack and holds the credentials, so it can call
`core_engine.run_backup_and_triage()` on itself with no changes to that
function.

## Design

Two directions, kept separate because they have different triggers and
different payload sizes.

### Agent to central, unprompted

Added to `Agent.cycle()` in `services/site_agent.py`, after `push_arp`:

1. **Status, every cycle.** The agent pings each device in its local inventory
   and posts the results. Cheap, and it is the only thing that gives an agent
   site a live up/down state.

2. **Triage + backup, every `backup_interval` seconds.** Default 3600, `0`
   disables. Deliberately not the polling interval: an operator running a 15
   second poll does not want a config backup every 15 seconds. The value rides
   the existing `_agent_config` job, exactly as `syslog_port` and `interval`
   already do, so the dashboard's config panel gains one field and no new
   settings plumbing is written.

The agent keeps writing its own local `data/backup-config/` copy as a side
effect of `run_backup_and_triage()`; it reads the text back from the saved path
to push. The local copy is not the deliverable, it is what the agent already
does.

### Central to agent, on demand

One value added to `VALID_JOB_KINDS` in `services/site_manager.py`: `triage`.
`Agent.run_jobs()` dispatches it to the same local function the scheduled phase
uses and pushes the payload through the endpoints below. The job's `result`
column carries a one-line summary (`"ok, 42 KB"`), never the config.

One kind, not two: `run_backup_and_triage` takes the backup *and* reads the
version in a single pass, so a separate `backup` kind would be a second name
for the same call with no caller to distinguish it.

That last point is a requirement, not a preference: `command_jobs.result` is an
unbounded `TEXT` column, so a config would fit — but it is rendered verbatim
into the job-history panel (`static/js/site-agent.js`), and a 200 KB config
there makes the panel useless.

### Endpoints

Both reuse the existing `get_agent_site` dependency in `routers/agent.py`, so
token authentication, site binding and `touch_last_seen()` come for free.

`POST /api/agent/status`

```json
{"devices": [{"ip": "192.0.2.20", "up": true},
             {"ip": "192.0.2.21", "up": false}]}
```

Central calls `update_version_inventory(ip, vendor, version, "online"|"offline")`
per entry, preserving the stored vendor and version — the same write the
central's own ping check performs today.

`POST /api/agent/backup`

```json
{"ip": "192.0.2.20", "hostname": "switch-01", "vendor": "cisco",
 "version": "15.2(7)E2", "serial": "ABC1234DEFG",
 "config": "<running-config text>"}
```

Central calls `backup_store.save_backup()` and `update_version_inventory()` —
the same functions a central-poll triage uses, so the topology map, config
drift and the model-based classifier populate for agent sites with no new
storage and no new readers.

**Both endpoints reject an IP not tagged to the calling site.** The known gap
where an authenticated agent receives all pending jobs (`docs/remote-sites.md`
§1) must not acquire a twin on the write path: one site's token must never be
able to overwrite another site's config or status.

### Central-side entry points

`POST /api/run-triage` (`routers/triage.py`) loops devices and calls
`run_backup_and_triage` directly, which since `b9ecd63` returns an error for
agent-site devices. It gains a branch: an agent-site device is enqueued with
`enqueue_job(site, ip, "", kind="triage")` and reported as **queued**.

That is the only central-side entry point that needs changing. Taking a backup
is not a route of its own — it is what `run_backup_and_triage` does, so
`/api/run-triage` covers both. `/api/download-backup` reads the stored file and
is unaffected: once the agent has pushed a config, it downloads like any other.

The operation stays asynchronous. The agent collects jobs on its polling
interval, so there is no blocking wait and no synchronous result to return; the
operator is told the work is queued, and sees it complete in the job history.

This reverses the *user-visible* half of `b9ecd63`: triage on an agent device
changes from "error" to "queued". The refusal stays for the direct path — the
central still never opens SSH to an agent-site device.

## Error handling

- A device the agent cannot reach is pushed as `up: false`. It is never
  omitted: a skipped device silently disappears from the ping monitor, which
  is the failure mode this whole change exists to remove.
- A failed triage pushes nothing and marks only the job `error`. A partial or
  empty push must never overwrite a good stored config.
- `config` is capped at 5 MB and rejected with a clear error rather than
  truncated. A truncated config that reaches `backup_store` is worse than no
  config: config drift would report a spurious change and the model classifier
  would read half a file.
- Every push failure is logged agent-side and retried on the next cycle. No
  queue, no backlog file: the next cycle regenerates current state anyway.

## Testing

- Agent cycle: ping and backup phases with `run_backup_and_triage` mocked —
  asserts the push happens, that `backup_interval: 0` disables the backup
  phase, and that an unreachable device is pushed as `up: false`.
- Both endpoints via `TestClient`: happy path, wrong token, and an IP
  belonging to another site (must be rejected).
- `run-triage` returns "queued" for an agent-site device and still runs
  directly for a central one.
- Round trip in `tests/test_remote_site.py`: a pushed config lands in
  `backup-config/<group>/` and its version appears in
  `detected_versions.json`.
- The size cap rejects an oversized config without writing anything.

## Out of scope

SNMP polling, the observability API poller, `l2_scheduler` and
`redundancy/service` still iterate the full inventory with no site filter, so
they will keep dialling agent-site devices directly. Guarding those four loops
is a separate, mechanical change.

Full parity — turning the job queue into a general RPC channel with typed
methods — was considered and rejected as premature: the two job kinds added
here are exactly the first two methods such a channel would carry, so nothing
here blocks it later.
