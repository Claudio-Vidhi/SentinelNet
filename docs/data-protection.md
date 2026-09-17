# Data protection

What personal data SentinelNet stores, where it lives, how long it stays, and
what an operator has to decide. This is a factual inventory so a data
protection assessment can be written against the software as it actually
behaves; it makes no claim about compliance, which depends on how the
installation is run.

Everything below lives under `SENTINELNET_DATA_DIR` (default `./data`) plus the
`backup-config/` tree. Both are excluded from the public repository as whole
directories — see [AGENTS.md](../AGENTS.md) §"Protect real data".

---

## 1. What is stored that can identify a person

Network monitoring is not usually thought of as personal-data processing, and
most of what this product holds is about equipment. Three categories are not.

### 1.1 Device and endpoint identifiers

| Data | Where | Why it is there |
|---|---|---|
| MAC addresses | `mac_history.db` (`mac_sightings`, `arp_entries`) | The MAC is the only stable identifier of a device on L2, and the product exists to answer "where is this device plugged in" |
| IP addresses (private and public) | `mac_history.db`, `observability.db` (`flow_aggregates`, `syslog_events`, `events`), `network_hosts.csv` | Inventory, flows, and the correlation between them |
| Hostnames | `network_hosts.csv`, `detected_versions.json`, `observability.db` | Naming an endpoint by hostname is what makes a report readable |
| Switch port and VLAN of an endpoint | `mac_history.db` | The physical position of a device |

A MAC or an IP is personal data whenever it can be tied to a person — a
laptop, a phone, a desk. In a corporate network that is usually the case, and
the honest assumption is that it is.

### 1.2 Traffic and log content

| Data | Where | Retention |
|---|---|---|
| Flow records (src/dst IP, port, protocol, bytes, aggregated per minute) | `observability.db` → `flow_aggregates` | 30 days (`SENTINELNET_OBS_RETENTION_FLOWS_DAYS`) |
| Syslog messages, verbatim | `observability.db` → `syslog_events` | 7 days (`SENTINELNET_OBS_RETENTION_SYSLOG_DAYS`) |
| Normalised events, evidence, incidents | `observability.db` | 30 days for events, 90 for evidence and incidents (`SENTINELNET_OBS_RETENTION_EVENTS_DAYS`) |
| MAC/ARP sightings | `mac_history.db` | 30 days from the last time the row was updated, configurable in the MAC Tracker tab |

**Syslog content is the widest exposure, and it is not something the product
controls.** A firewall can log a username, a visited URL, or an email address;
SentinelNet stores the line as sent. The 7-day default is short for that
reason, and the shipped configuration does not receive syslog at all (see §2).

### 1.3 People who use SentinelNet

| Data | Where | Notes |
|---|---|---|
| Usernames, bcrypt password hashes, role, tenant scope, email, last sign-in time, approval state | `users.json` | Owner-only file permissions; the email is used for password recovery; the last sign-in is overwritten at each login, not a history |
| Pending recovery-address confirmations | Process memory only | One-hour single-use tokens; lost on restart |
| Login attempts, per source and account | `login_attempts.json` | Lockout state, pruned after the lockout window |
| Audit trail: who did what, when, from which declared client | `audit.log` | 10 MB × 9 rotated files. HMAC-chained, so a rewritten line is detectable |
| Revoked session identifiers | `revoked_tokens.json` | Each entry lives only until the token it names would have expired |
| AI conversations | `observability.db` → `ai_conversations` | Kept per user until deleted from the panel. **No automatic retention** |
| Notification preferences and admin rules (recipient addresses, tenants, quiet hours) | `observability.db` → `notify_prefs`, `notify_rules` | Kept until changed or deleted |
| Notification send history: recipient, event title, status, error | `observability.db` → `notify_log` | 30 days. Non-admins see only their own rows |
| Pending notifications | `observability.db` → `notify_outbox` | Deleted once sent, or after three failed attempts |

Device credentials (`network_hosts.csv`, `identities.json`) are encrypted with
the Fernet key in `secret.key`. They are secrets rather than personal data, but
they are why `SENTINELNET_DATA_DIR` deserves the protection of a password
vault.

---

## 2. What the shipped configuration does *not* collect

Defaults matter for an assessment, so they are stated here rather than left to
be inferred from the code:

- **All observability listeners are off.** No flows, no sFlow, no syslog are
  received until `SENTINELNET_OBS_ENABLE=1`, and even then each listener needs
  its own switch and binds to loopback unless told otherwise
  ([hardening.md](hardening.md) §4).
- **The SNMP, Linux and L2 pollers are off** (`*_poll_s` default 0).
- **No email is sent** until an SMTP server is configured.
- **Two MCP tools plus `linux_health` are disabled by default**, so an AI
  assistant does not reach flow data or host health until an admin enables them
  ([hardening.md](hardening.md) §7).
- **No telemetry leaves the installation.** The only outbound traffic the
  product initiates is to the devices it manages, to the vulnerability feeds
  when asked, and to an AI provider if one is configured.

An installation that uses only inventory, backup and the MAC tracker therefore
stores MAC/IP/hostname and nothing from §1.2.

---

## 3. What an operator has to decide

These are choices the software cannot make:

1. **Retention.** The defaults above are what the code applies; whether 30 days
   of flows is proportionate to the purpose is a local decision. All four
   windows are environment variables or advanced settings, and shortening one
   takes effect at the next hourly prune.
2. **Whether to receive syslog at all.** It is the only source that can carry
   arbitrary personal data in its payload, and it is off by default.
3. **An AI provider is a transfer to a third party.** Outbound messages pass
   through `redact()`, which removes credentials and masks addresses (finding
   I-1) — that is a reduction, not anonymisation: a hostname or a topology can
   still identify an organisation. A local model on the same host avoids the
   transfer entirely.
4. **Who gets an account, and scoped to which tenants.** An account with no
   tenant restriction reads every tenant, by design.
5. **Where the data directory lives, and who can read it.** The product
   restricts the files it creates to the account that runs it; it cannot fix a
   directory that was already shared.
6. **Answering a subject access or erasure request.** There is no built-in
   export or delete for "everything about this endpoint". What exists: the
   Client Map and Endpoint Inventory search by MAC or IP and export CSV, and
   the retention windows delete on their own. Anything narrower is a manual
   operation on the two SQLite files.

---

## 4. Deleting data

| Target | How |
|---|---|
| One endpoint's MAC/ARP history | No dedicated action: it disappears with retention. A targeted delete is a manual `DELETE` on `mac_history.db` |
| Flows, syslog, events | Shorten the retention window; the hourly prune applies it |
| An AI conversation | Delete it from the AI tab |
| A user | Delete from the Users tab. Their sessions stop working immediately, and their name stays in the audit trail — which is the point of an audit trail |
| Everything | Stop the service and remove `SENTINELNET_DATA_DIR` and `backup-config/`. There is no other copy unless cloud backup was configured |

---

## 5. Where this is enforced in code

Not a substitute for reading it, but the entry points:

- Retention windows: `core/data_config.py` → `obs_config()["retention_days"]`,
  applied by `observability/rollup.py` → `prune_once`.
- MAC/ARP retention: `collectors/mac_history.py` → `get_retention_days()`.
- File permissions on the sensitive files: `core/data_config.py` →
  `restrict_permissions()`.
- Redaction before any AI provider: `security/redaction.py` → `redact()`, called from
  `ai_assistant.chat()` and `mcp_server.api()`.
- Tenant scoping of every read: `routers/deps.py` → `user_group_scope()`.
- Audit trail and its tamper-evidence: `security/security_manager.py` →
  `log_audit()`, `verify_audit_chain()`.
