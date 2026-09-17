# Collectors — where the data comes from

Each source writes to its own raw table; from there an adapter in
[normalize.py](../observability/normalize.py) projects it into the event model.
That's the whole contract: a new source costs a decoder and an adapter, and
nothing else. See [architecture.md](architecture.md) §2.

No collector is enabled by default. Configuration and exposure:
[operations.md](operations.md) §3 and [hardening.md](hardening.md) §4.

---

## 1. Overview

| Source | Transport | Default port | Module | Table |
|---|---|---|---|---|
| IPFIX | UDP | 4739 | [ingesters/ipfix.py](../observability/ingesters/ipfix.py) | `flow_aggregates` |
| NetFlow v9 / v5 | UDP | 2055 | same decoder | `flow_aggregates` |
| sFlow v5 | UDP | 6343 | [ingesters/sflow.py](../observability/ingesters/sflow.py) | `flow_aggregates` |
| syslog | UDP | **5514** | [ingesters/syslog.py](../observability/ingesters/syslog.py) | `syslog_events` |
| FortiGate REST | outbound HTTPS | — | [ingesters/api_poller.py](../observability/ingesters/api_poller.py) | `api_observations` |
| SNMP v2c | outbound UDP 161 | — | [ingesters/snmp_poller.py](../observability/ingesters/snmp_poller.py) | `api_observations` |
| Linux health | outbound SSH | 22 | [ingesters/linux_poller.py](../observability/ingesters/linux_poller.py) | `api_observations` |
| Windows health | outbound SSH | 22 | [ingesters/windows_poller.py](../observability/ingesters/windows_poller.py) | `api_observations` |
| Site agent | inbound HTTPS | 8000 | [services/site_agent.py](../services/site_agent.py) | inventory, MAC, syslog |
| ARP / MAC tables | SSH · NETCONF · RESTCONF | — | [collectors/](../collectors/) | `mac_history.db`, `arp_entries` |

The first four are **passive**: devices send, SentinelNet listens. The rest are
**active polling**: SentinelNet asks.

---

## 2. The common UDP listener path

Applies to IPFIX, NetFlow, sFlow and syslog
([ingesters/udp_server.py](../observability/ingesters/udp_server.py)):

```
datagram_received  →  put_nowait on an asyncio queue (max 20,000)
                      NO parsing, NO DB, NO task per packet
        ▼
consumer (1 task per listener)  →  parse()  →  tenant resolution
        ▼
db.enqueue_flow() / enqueue_write()  →  bounded queue, 10,000
        ▼
writer thread  →  batch commit of 500  →  observability.db (WAL)
```

The choices holding this together:

- **A separate ingest loop** from FastAPI's, on its own thread. A burst of tens
  of thousands of datagrams must not make the WebSocket terminal and the API
  unresponsive.
- **Queue full → drop**, with a `dropped_queue_full` metric. Losing packets in a
  measured way beats blocking the loop.
- **GIL switch interval lowered to 1 ms**: the parsing thread is CPU-bound in
  bursts, and at the 5 ms default the main loop was waiting tens of milliseconds
  under load.
- **Yield every 20 records** in the consumer: with a full queue `queue.get()`
  returns without suspending, and without the yield the consumer would starve
  its own loop.
- **No parser ever raises**: malformed input yields whatever decodes and bumps
  `parse_errors`. One device sending garbage doesn't stop ingestion for the
  others.

### 2.1 Tenant attribution

The datagram's source IP is resolved against the inventory. An exporter not in
inventory (or a collision between two devices with the same IP) → **records
dropped**, upsert into `quarantined_exporters`, one audit entry rate-limited to
1/hour per exporter, `dropped_unknown_exporter` metric.

No record is ever written with a fallback tenant. See
[ADR-0005](adr/0005-strict-tenant-attribution.md).

**Known limitation (NAT):** attribution uses the datagram's source IP, so an
exporter behind NAT would be misattributed. Handle it with a site relay, not by
exposing UDP over the VPN.

### 2.2 Clock skew

The exporter's timestamp is used only if it is within ±300 s of reception;
otherwise reception time is used and `clock_skew_fallback` is incremented. A
device with a wrong clock must not be able to write buckets into the future or
the distant past.

---

## 3. IPFIX and NetFlow

A single decoder for IPFIX (RFC 7011), NetFlow v9 and NetFlow v5.

Normalized record: `src_ip`, `dst_ip`, `protocol`, `dst_port`, `bytes`,
`packets`, `flow_end_ts`, `exporter_ip`.

**Template handling** (v9 and IPFIX), which is where the real complexity lives:

- cache keyed by `(exporter_ip, observation_domain_id, template_id)`, bounded to
  1024 with oldest-first eviction and a 1800 s TTL;
- **data sets that arrive before their template**: buffered (bounded to 256) and
  re-decoded when the template shows up. This is the normal case after an
  exporter restart, not an anomaly — dropping them would mean losing the first
  minute of every session;
- template re-announcement: clean replacement, and the pending buffer for that
  key is retried;
- unrecognized IEs are skipped using only their length. Variable-length fields
  and enterprise numbers are handled per RFC.

### 3.1 Aggregation

`flow_aggregates` is **not a flow log**: it's a per-minute rollup. The UPSERT is
on `UNIQUE(window_start, tenant, src_ip, dst_ip, protocol, dst_port)` with
`window_start` truncated to the minute, and `flow_count` counts how many flow
records landed in the bucket.

Consequence worth remembering when reading downstream code: the normalization
adapter re-reads buckets until the window closes and **updates** metrics on
conflict rather than ignoring them.

---

## 4. sFlow

**The emitted values are estimates, and that is binding.** sFlow samples one
packet every `sampling_rate`, so for each flow sample:

```
bytes   = frame_length * sampling_rate
packets = sampling_rate
```

Counter samples are not used: the header is read, the body skipped,
`counter_samples_skipped` incremented. Per-interface state comes from SNMP (§6),
which gives it exactly rather than sampled.

---

## 5. Syslog

Formats: RFC 3164 (BSD) and RFC 5424, with vendor normalization for FortiGate
(`key=value` body) and Palo Alto (TRAFFIC/THREAT CSV).

Output: unix UTC `ts`, `device_ip`, `severity` 0-7, `action`, `message`
truncated to 2048 characters (log minimization).

Unknown format → `action=None` and the raw message preserved. No field is
invented: whatever the message doesn't contain stays `None`, and the UI shows a
dash.

**Port 5514, never 514 in-process.** 514 is privileged; if it's needed, map it
from compose (`"514:5514/udp"`).

`syslog_events` is the only table that holds **real device verdicts**
(ALLOW/DENY): `flow_aggregates` are counters and have no notion of them. That's
why Flow SIEM reads from here and not from there — see
[live-flows-and-siem.md](live-flows-and-siem.md) §7.1 for what happened
when that distinction was ignored.

Field extraction from the message body lives in exactly one place,
[fieldmap.py](../observability/fieldmap.py): two parsers over the same messages
would give two different results for the same event depending on who's looking.

### 5.1 Linux and Windows servers

Nothing server-specific runs on this side: the receiver parses the RFC 5424
line a server sends like any other, and attributes it by **source IP** against
inventory (§2.1). Two conditions, both on the sending side:

1. **The server is in inventory**, with the IP its syslog packets leave from.
   A server not in inventory — or one sending from a second interface — is
   quarantined, not stored.
2. **It sends UDP to the configured port** (default 5514). The listener is UDP
   only: TCP or TLS syslog is not accepted. UDP loses messages under load and
   travels in clear, so keep it on a management network; for a server at a
   remote site use the site agent, not UDP over the VPN.

Enable the listener first: Settings → Observability, syslog on.

#### Linux (rsyslog)

`/etc/rsyslog.d/60-sentinelnet.conf`, replacing the address with the
SentinelNet host:

```
# Everything at notice and above, RFC 5424 with a full timestamp and offset.
*.notice action(type="omfwd" target="192.0.2.5" port="5514" protocol="udp"
                template="RSYSLOG_SyslogProtocol23Format")
```

Then `systemctl restart rsyslog`, and `logger -p auth.warning test-sentinelnet`
on the server should show up in Flow SIEM.

Why the template: rsyslog's default forwarding format is RFC 3164, whose
timestamp carries neither year nor time zone, so the receiver has to assume
both (§5). RFC 5424 carries them.

Why `notice` and not `*.*`: `info` and `debug` on a busy server are thousands of
lines a minute, all kept under the same retention as firewall verdicts. Widen
it per facility (`auth,authpriv.*`) when a question needs it.

#### Windows (NXLog)

**Windows does not speak syslog.** The Event Log has no native forwarder to a
syslog receiver — Windows Event Forwarding sends to another Windows collector,
not here — so a Windows server needs an agent. NXLog Community Edition is free
and the usual choice; the trade-off is one more service to install, update and
monitor on every server.

`C:\Program Files\nxlog\conf\nxlog.conf`, after the default header:

```
<Extension syslog>
    Module  xm_syslog
</Extension>

<Input eventlog>
    Module  im_msvistalog
    # Errors and warnings from System and Application, plus Security.
    <QueryXML>
        <QueryList><Query Id="0">
            <Select Path="System">*[System[(Level=1 or Level=2 or Level=3)]]</Select>
            <Select Path="Application">*[System[(Level=1 or Level=2 or Level=3)]]</Select>
            <Select Path="Security">*</Select>
        </Query></QueryList>
    </QueryXML>
</Input>

<Output sentinelnet>
    Module  om_udp
    Host    192.0.2.5
    Port    5514
    Exec    to_syslog_ietf();
</Output>

<Route r>
    Path    eventlog => sentinelnet
</Route>
```

Then `Restart-Service nxlog`. `to_syslog_ietf()` writes RFC 5424, same reason as
the rsyslog template. The whole Security log is a lot of volume on a domain
controller; narrow it to the event IDs that matter (4625 failed logon, 4740
lockout, 4720 account created) once it works.

The two line shapes above are fixed in
`tests/test_observability_ingest.py::TestAttribution::test_server_syslog_lands_on_the_inventory_host`.

---

## 6. SNMP v2c

Fills the gap REST leaves: per-device state only arrives from FortiGates with a
token, so switches — the majority of any network — would contribute nothing to
the reasoning.

- **Numeric OIDs, no MIB resolution.** See
  [ADR-0007](adr/0007-numeric-snmp-oids.md).
- **Reads only, v2c only.** No SET: a compromised community cannot change a
  device. The community still travels in clear text — a protocol limitation, not
  an implementation one: management network only.
- **`ifName` as the key**, not `ifIndex`: it's the name the engineer sees on the
  device, and `ifIndex` changes across reboots on several vendors.
- 200 interfaces per device cap: one large chassis must not stall the round for
  everyone else.
- **The access VLAN is collected too, and IF-MIB has no column for it.** Without
  it, moving a port to another VLAN produced *nothing*: the VLAN wasn't in the
  snapshot, so it couldn't change, so `CFG_CHANGE_001` — which fires on
  `interface.change` — had nothing to see. A port that is up in the wrong VLAN
  is indistinguishable from a port that is up, and to whoever is plugged into
  it that is exactly an outage. Two sources, same "whoever answers wins" pattern
  as the CPU OIDs: `vmVlan` (CISCO-VLAN-MEMBERSHIP-MIB, indexed by `ifIndex` —
  what Cisco switches actually populate for access ports), falling back to
  `dot1qPvid` (Q-BRIDGE, vendor-neutral but indexed by `dot1dBasePort`, hence
  the extra `dot1dBasePortIfIndex` walk to translate it). A device that answers
  neither — a router, a firewall — simply carries no `port_vlan` field, rather
  than a zero that would read as a real VLAN.

Snapshots land in the **same** `api_observations` as the REST poller, with
`kind` `snmp_system` / `snmp_interfaces` and the same
`{"results": {"<ifName>": {field: value}}}` shape. That's not clever reuse: it's
that nothing downstream should change. The transport changes, the fact doesn't.

### 6.1 Interface error counters

Each `snmp_interfaces` snapshot also carries the Ethernet error set:
`ifInErrors`/`ifOutErrors`, `ifInDiscards`/`ifOutDiscards` and the
EtherLike-MIB `dot3StatsTable` (FCS/CRC, alignment, symbol, late and
excessive collisions, carrier sense, frame too long, internal MAC
receive/transmit errors). The vocabulary and the verdict live in one place,
[observability/iface_errors.py](../observability/iface_errors.py), whatever
transport brought the numbers in:

- **Growth, not totals.** Counters are cumulative since boot or the last
  clear, so a switch up for two years carries errors that stopped long ago.
  Only the increment inside the window (1h / 24h / 7d) counts, and a counter
  that goes down — a reboot, a `clear counters` — restarts from there instead
  of producing a negative or an invented jump.
- **Garbage is dropped, not believed.** Some agents return nonsense for the
  detailed counters (billions of CRC errors on a port whose `ifInErrors` is
  0): a detail counter larger than its total is discarded. Plain collisions
  are not counted — normal on half duplex, unreliable on several agents —
  while late and excessive collisions stay, because they are the
  duplex-mismatch signal.
- **Absent is not zero.** A counter the device does not expose stays absent
  ("unknown"); zero means "clean".

Each port gets one verdict — physical (cable/optic), duplex, hardware, generic
errors, or discards only — used identically by the Interfaces tab, the
endpoint detail, port occupancy, the *Port errors* view and client diagnosis
(`/api/interface-errors`, tenant-scoped like every device route).

**On demand.** *Read errors now* (`POST /api/interface-errors/read`,
operator) takes two readings ten seconds apart: over SNMP when the device has
a community, otherwise over SSH with one command per driver
([collectors/iface_counters_cli.py](../collectors/iface_counters_cli.py)) —
`show interfaces` on Cisco IOS/IOS-XE/NX-OS and ProCurve,
`show interfaces extensive` on Junos, `show interface` on AOS-CX,
`diagnose netlink interface list` on FortiOS, `show counter interface all` on
PAN-OS. Parsers read label/value pairs rather than fixed columns, and an output
they do not recognise yields nothing, never zeros. Cisco CBS prints error
counters one port at a time and is left to SNMP. Results are stored in
`iface_counter_reads`, pruned with the poller snapshots.

---

## 7. FortiGate REST

Periodic polling of FortiGates with a configured API token: `system_status` and
`interfaces` as compact snapshots (20,000-character cap) into
`api_observations`. The GUI and the AI assistant read from the database instead
of hitting the device on every view.

The `requests` calls are blocking and are off-loaded to threads. Per-device
failures are best-effort: log and move on.

The normalization adapter turns these snapshots into both `device.state` /
`interface.state` and `device.change` / `interface.change`, by comparing
consecutive snapshots. Fields that are volatile by construction (counters,
uptime, sessions) are excluded from the comparison via a substring filter —
without it, every round would produce a "change" on every port of every device.

---

## 7b. Linux health

A Linux server exposes neither a REST API like a FortiGate nor, as a rule, an
SNMP agent: without this poller it would be a device you can query by hand but
that contributes nothing to incident reasoning.

One SSH session per host, one command
([`PROBE_COMMAND`](../observability/ingesters/linux_poller.py)), snapshots into
the same `api_observations` with `kind` `linux_health`. Nothing downstream
changes: `normalize._from_api_observations` already projects them into
`device.state`, and `DEVICE_LOAD_001` already reads `cpu_pct` / `memory_pct` /
`disk_pct` from `events.metrics_json` without knowing where they came from.

| Branch | Fields |
|---|---|
| `results` (compared) | `kernel`, `uptime_s`, `failed_units` |
| `metrics` (never compared) | `cpu_pct`, `memory_pct`, `disk_pct`, `load1`, `load5`, `load15`, `zombies`, `pending_updates` |

- **CPU is a delta**, not an average: `/proc/stat` is read twice a second apart,
  because the raw file is a counter since boot.
- **Memory uses `available`**, not `used`: buffers and page cache are reclaimable,
  and counting them as used would make any host that read a large file look full.
- **The `metrics` branch is excluded from change detection**
  ([`_stable_fields`](../observability/normalize.py)). A measurement changes on
  every read — that's its job. Comparing it would report a "configuration change"
  every polling round.
- **Absent ≠ zero.** A missing section yields no field at all: a threshold rule
  reading zero would stay silent exactly where it isn't looking.
- **No sudo.** Every metric here is readable by an unprivileged account, so the
  session never calls `enable()`. The privileged tier exists only in triage.
- **Central sites only.** Hosts behind a site agent in `mode == 'agent'` are not
  polled; supporting them means adding the round to `services/site_agent.py`.

### Windows hosts

The same loop and the same `linux_poll_s` interval also poll hosts with vendor
`windows`, through [`windows_poller`](../observability/ingesters/windows_poller.py):
one PowerShell command over SSH, `kind` `windows_health`, event `source`
`windows`. Only `cpu_pct` / `memory_pct` / `disk_pct` (system drive), enough for
`DEVICE_LOAD_001`; `results` stays empty.

- **SSH, not SNMP**: the SNMP service on Windows is a deprecated optional
  feature, OpenSSH is already a prerequisite of the platform.
- **Integers only on the wire**: the command prints `LoadPercentage`, kilobytes
  and bytes joined with `|`, and the percentages are computed in Python. A
  formatted number would carry the host's localised decimal separator.
- **CPU is `LoadPercentage`**, which Windows already averages over roughly a
  second; several sockets are averaged together. A hypervisor that leaves it
  empty yields no `cpu_pct`, not zero.

---

## 8. Site agents

For sites in *site agent* mode, the agent collects locally and pushes outbound
over HTTPS to central: inventory, MAC tables, batched syslog
(`POST /api/agent/syslog`, stored tagged by site and tenant), and CLI job
results.

Device credentials stay in the agent's data directory; only metadata goes to
central. Full guide: [remote-sites.md](remote-sites.md).

---

## 9. ARP and MAC tables

These aren't observability: they feed the Client Map and the position history,
which the flow path and the correlator then re-read to answer "*where* is that
IP plugged in".

- [arp_collector.py](../collectors/arp_collector.py) — ARP tables from L3
  gateways (that's where the IP↔MAC↔VLAN binding is authoritative);
- [mac_collector.py](../collectors/mac_collector.py) — MAC tables over CLI,
  NETCONF or RESTCONF, per the transports declared on the device;
- [mac_history.py](../collectors/mac_history.py) — sighting history,
  reclassification, uplink detection, manual overrides.

Both are pushed by remote site agents too (`POST /api/agent/mac`,
`POST /api/agent/arp`). ARP in particular is not optional at a remote site:
`arp_entries` holds the only MAC↔IP binding, so without it a remote client has
a switch port but no address — and Client Map, flow path and client diagnosis
all start from the IP.

**Both are collected on demand, not on a schedule.** Nothing in
`listener_manager` triggers them; they run from the ARP/MAC scan buttons or
from a site agent's cycle. Anything reading this data should surface
`last_seen` / `port_last_seen` rather than presenting a three-week-old port as
current — which is why the client diagnosis carries both dates into its report.

**Mind the timestamps**: `mac_history.db` uses ISO-8601 text while
`observability.db` uses unix integers. Conversion happens at the boundary, in
[timeline.py](../observability/timeline.py). Never compare them directly.

---

## 10. Adding a source

1. A decoder returning normalized records, in `observability/ingesters/`. It
   must not raise: bump `parse_errors` and move on.
2. If UDP: an entry in `_listener_specs`
   ([listener_manager.py](../observability/listener_manager.py)) and the config
   keys in [core/data_config.py](../core/data_config.py). If polling: a periodic
   task, started from the same place.
3. Write via `db.enqueue_*`, **never** raw `sqlite3` in async code
   ([CONTRIBUTING.md](../CONTRIBUTING.md) §3).
4. An adapter in [normalize.py](../observability/normalize.py) projecting into
   `events` with a deterministic `dedup_key`.
5. `test_observability_ingest.py` for the decoder,
   `test_unified_event_model.py` for the adapter.

Rules, incidents, timeline and UI need no changes: if the event model is
respected, the source inherits them.
