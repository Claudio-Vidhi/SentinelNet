# Operations runbook

What you need when something breaks and the code doesn't tell you. Installation
and environment variables are in [../README.md](../README.md); safe exposure is
in [hardening.md](hardening.md).

---

## 1. Where things live

All state lives in **one** directory, resolved by
[core/data_config.py](../core/data_config.py):

```
SENTINELNET_DATA_DIR   if set
./data                 otherwise (relative to the process CWD)
```

It is not the executable's directory: an exe launched from another folder looks
for `data/` next to *that*. First thing to check when "the data disappeared".

| File | Contents |
|---|---|
| `network_hosts.csv` | Inventory, credentials **encrypted** with Fernet |
| `observability.db` (+ `-wal`, `-shm`) | Flows, syslog, events, evidence, incidents |
| `mac_history.db` | MAC position history, ARP |
| `redundancy.db` | HA group state |
| `users.json` | Local accounts, bcrypt |
| `groups.json` / `sites.json` | Groups and sites |
| `app_settings.json` | GUI configuration (observability, rule thresholds, suppressions, preview flags) |
| `fortigate_tokens.json` | FortiGate API tokens, encrypted |
| `secret.key` / `jwt_secret.key` | Local cryptographic keys |
| `detected_versions.json` | Firmware triage cache |
| `audit.log` | Security log, rotating |
| `error_log.txt` | SSH engine exceptions |
| `backup-config/<group>/<vendor>/` | Device running-configs |

`secret.key`, `jwt_secret.key`, `users.json`, `sites.json` and `mac_history.db`
get restrictive ACLs at creation (best effort: `icacls` on Windows, `chmod 600`
elsewhere).

**One-time migration:** state files found in the CWD are moved into `DATA_DIR`
on first start. If a file exists in both places, `DATA_DIR` is authoritative.

---

## 2. Logs and diagnostics

| Where | What's in it |
|---|---|
| Process stdout/stderr | Startup, listeners, tasks, poller errors |
| `audit.log` | Logins, CLI commands, blacklist bypasses, config changes, quarantined exporters |
| `error_log.txt` | `core_engine` exceptions (SSH, backup, triage) |
| `GET /api/observability/health` (**admin**) | Active listeners, in-process metrics, DB size |

`/health` is the first place to look for observability: it tells you whether
listeners are up, how many packets were dropped and why. Counters worth reading:

| Metric | Meaning |
|---|---|
| `dropped_queue_full` | Ingest faster than the writer: queue saturated |
| `dropped_unknown_exporter` | Exporter not in inventory (§4) |
| `parse_errors{proto=…}` | Malformed datagrams, per protocol |
| `data_before_template_dropped` | IPFIX/v9 data sets without a template, buffer full |
| `clock_skew_fallback` | Exporter clock off by more than 300 s |
| `listener_bind_failed` | Port busy or privileged |
| `writes_dropped_error` | Payloads rejected by the writer after rollback |
| `counter_samples_skipped` | sFlow counter samples ignored (normal) |

---

## 3. Observability: enabling and changing it

Everything is off by default, everywhere. The master switch turns listeners on;
the SNMP poller still stays off until given an interval, because it queries
devices with a credential and must not start on its own.

Precedence: **environment variables > `app_settings.json` > defaults**.

```
SENTINELNET_OBS_ENABLE=1          # master switch
SENTINELNET_OBS_BIND=127.0.0.1    # 0.0.0.0 requires explicit opt-in
SENTINELNET_OBS_IPFIX_PORT=4739    SENTINELNET_OBS_IPFIX_ENABLE=1
SENTINELNET_OBS_NETFLOW_PORT=2055  SENTINELNET_OBS_NETFLOW_ENABLE=1
SENTINELNET_OBS_SFLOW_PORT=6343    SENTINELNET_OBS_SFLOW_ENABLE=1
SENTINELNET_OBS_SYSLOG_PORT=5514   SENTINELNET_OBS_SYSLOG_ENABLE=1
SENTINELNET_OBS_API_POLL_S=300     # 0 = off
SENTINELNET_OBS_SNMP_POLL_S=0      # 0 = off (default)
```

From the GUI: `GET/POST /api/observability/config` (admin), settings tab.
**Applied hot, no process restart**: `apply_obs_config()` is idempotent,
computes the diff against active listeners and does stop-before-start for the
same name — mandatory on Windows, which won't allow double-binding a port.

A failed bind **does not stop the app**: metric, state in `listener_status`,
error log, listener skipped.

### Retention

Hourly job, DELETEs batched at 5000 rows to avoid holding long locks.

| Table | Default | Variable |
|---|---|---|
| `flow_aggregates` | 30 days | `SENTINELNET_OBS_RETENTION_FLOWS_DAYS` |
| `events` | 30 days | Same — the projection must not outlive its origin |
| `syslog_events` | 7 days | `SENTINELNET_OBS_RETENTION_SYSLOG_DAYS` |
| `evidence` (orphans) | 90 days | `SENTINELNET_OBS_RETENTION_EVENTS_DAYS` |
| `incidents` (`resolved` only) | 90 days | Same |

Unresolved incidents are never deleted automatically. Evidence attached to an
incident follows it via `ON DELETE CASCADE`; the job only prunes orphans.
`siem_suppressions` is outside retention: suppressions outlive the event they
point at (harmless orphan rows).

---

## 4. Symptoms and causes

### "The Live Flows tab is empty"

In order:

1. Does `/health` say observability is off, or zero listeners? The UI banner
   already states this — absence of data must not be silent.
2. Is `dropped_unknown_exporter` climbing? The exporting device is **not in
   inventory** under that IP. Check `quarantined_exporters` and the audit log.
   This is the most common case: export gets configured on the device before the
   device is registered.

   **Before adding it to inventory, look at the IP itself.** If the quarantined
   address is the *server's own* address, or a router's, it is not the exporter
   — a NAT rewrote the source address in transit. The give-away: the device is
   already in inventory under its real IP, and a second, different IP keeps
   getting quarantined. Typical setup that produces it — a hypervisor NAT
   network:

   | | |
   |---|---|
   | Host (SentinelNet) | `192.0.2.10` on the LAN, `198.51.100.1` on the NAT network |
   | Exporter VM | `198.51.100.20`, in inventory |
   | Listeners bound to | `192.0.2.10` only |

   The VM has to send to `192.0.2.10`, so its packets cross the NAT device,
   which rewrites the source to the host's own address — and that is what gets
   quarantined. Fix by removing the NAT from the path: bind the listeners to
   `0.0.0.0` and point the device's export at `198.51.100.1`, the interface it
   reaches directly. The source IP then stays `198.51.100.20`.

   **Never register the NAT-rewritten address as a device.** It would attribute
   the flows of everything behind that NAT to a device that does not exist, and
   expose them to the wrong tenant — precisely the damage the drop prevents
   ([ADR-0005](adr/0005-strict-tenant-attribution.md)).
3. Is `parse_errors` climbing? Unsupported protocol version or vendor.
4. `listener_bind_failed`? Port busy (another instance, or the exe running while
   you run tests) or privileged.
5. No metric moving at all? The device isn't exporting, or the UDP traffic isn't
   arriving. Verify from the device, not from here.

### "An alarm didn't fire"

1. Active suppression on the entity? `app_settings.json` → `suppressions`, and
   remember a device-level suppression covers **every** one of its interfaces.
2. Precision-over-recall: without corroborating flow within ±120 s nothing is
   emitted, except for severity ≤ 3. That's intended.
3. A baseline with fewer than 2 samples emits nothing: the first hours after a
   clean deploy are blind by construction.

### "The exe can't find its data / starts from scratch"

`SENTINELNET_DATA_DIR` unset and the CWD differs from the previous launch. See
§1.

### "The app is slow or the WebSocket terminal stalls"

Almost always synchronous `sqlite3` on an async path. Check:

```sh
grep -rn "get_observability_connection" routers/ observability/ingesters/ app_server.py
```

Only migrations and tests should show up. See
[CONTRIBUTING.md](../CONTRIBUTING.md) §3.

### "Observability refuses to start"

`SchemaTooNewError`: the database declares a schema version newer than the code
— typically an exe downgrade over a `DATA_DIR` already used by a newer build.
Fatal on purpose: better not to start than to write to an unknown schema. Fix:
put the newer build back, or start from a fresh `observability.db`.

### "A CLI command stays `queued` forever"

Agent-mode site with the agent stopped, or an IP missing from the agent's
**local** inventory. See [remote-sites.md](remote-sites.md) §5.

---

## 5. FortiGate tokens

Stored encrypted in `fortigate_tokens.json`, per IP:
`{"<ip>": {"token_enc": …, "port": 443, "verify_tls": false}}`.

Managed from the admin panel in the provisioner tab: save, remove, test. An
empty token means removal.

Without a token a FortiGate still works over the **SSH fallback**: slower and
with fewer fields, but nothing breaks. If FortiGate views show stale or
incomplete data, check the token state first.

---

## 6. Rebuilding the executable

```powershell
pwsh scripts/build.ps1          # pyinstaller + smoke test
pwsh scripts/build.ps1 -SkipSmoke
```

The smoke test launches `dist\SentinelNet.exe` on port 18443, loopback, UDP
listeners off (so it won't collide with a real instance), and checks it responds
within 60 s. Any HTTP response — 401 included — counts as alive.

**Every new data file must be added to `datas` in `SentinelNet.spec`** and
verified in all three modes: source, exe, Docker. Bundled paths resolve via
`sys._MEIPASS`. A `.sql` or `.json` that works from source and vanishes in the
exe is always this.

There is no CI: the build is local, deliberately.

---

## 7. Backup and restore

What to save: the entire `DATA_DIR`. Without `secret.key` the encrypted
credentials in `network_hosts.csv` and the FortiGate tokens are
**unrecoverable**; without `jwt_secret.key` all sessions drop (an annoyance, not
a loss).

The SQLite files are in WAL mode: copy them with the process stopped, or via
`sqlite3 … ".backup"`. Copying just the `.db` and leaving behind the `-wal` of a
live process produces a stale backup without telling you.

Restore: stop the process, put the directory back, restart. Migrations are
forward-only and idempotent.

## Pinning the mirror host key

Until `Host key (SHA256)` is filled in, the first connection accepts whatever
key the server presents - a redirected DNS record is then enough to hand the
backup credential to someone else. Pin it once, at setup:

1. Fill in host, user, authentication and remote folder (absolute path, it must
   start with `/`), then Save.
2. Press **Prova connessione / Test connection**. The toast reports the
   fingerprint the server presented, and the field is filled in with it.
3. Check that fingerprint against the server itself
   (`ssh-keyscan -t ed25519 backup.example.net | ssh-keygen -lf -`), then Save.

From then on a server presenting a different key is refused during the
handshake, before any credential is sent. Rotating the server key means
clearing the field, testing again and re-pinning.

## Restoring from the offsite mirror

The mirror is write-only: the app never reads it back. Recovering is a manual,
documented procedure - verify it once, by hand, before you need it.

1. Copy the archive locally:
   `scp -r user@backup.example.net:/srv/backups/sentinelnet ./archive`
2. Inspect `archive/_manifest.json`: `updated_at` is when the copy was last
   refreshed, `encrypted` says whether the files are ciphertext.
3. Rebuild the tree with the script shipped alongside it:

   ```sh
   python archive/restore.py --source archive --target ./restored
   # encrypted archive:
   python archive/restore.py --source archive --target ./restored --key-file fernet.key
   ```

4. Copy what you need back under `backup-config/<tenant>/<vendor>/`. Current
   configs keep their name; previous versions live in `.history/` with their UTC
   timestamp in the filename and are indexed by `<ip>-index.json`.

The Fernet key for an encrypted archive is the one in this install's key store.
Without it the copy cannot be read - which is why enabling encryption comes with
backing that key up separately, offline.

---

## 8. Limits to know before scaling

- **Single-process SQLite writer.** Never `--workers > 1` with observability
  enabled. Observability does not scale horizontally
  ([ADR-0004](adr/0004-single-process-sqlite-writer.md)).
- **UDP ingest is unauthenticated.** Expose it only on trusted management
  networks.
- **Tenant attribution by source IP.** Exporters behind NAT need a site relay,
  not UDP opened over the VPN.
- **Flow SIEM deep scan**: up to 20,000 rows parsed in Python per request,
  repeated every 5 s by the live tail. If it becomes a problem, the path is
  materializing the derived fields as columns at ingestion, not optimizing the
  loop ([live-flows-and-siem.md](live-flows-and-siem.md) §9).
