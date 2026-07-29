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
| Site agent | inbound HTTPS | 8765 | [services/site_agent.py](../services/site_agent.py) | inventory, MAC, syslog |
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

Snapshots land in the **same** `api_observations` as the REST poller, with
`kind` `snmp_system` / `snmp_interfaces` and the same
`{"results": {"<ifName>": {field: value}}}` shape. That's not clever reuse: it's
that nothing downstream should change. The transport changes, the fact doesn't.

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
