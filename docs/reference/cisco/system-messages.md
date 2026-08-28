# IOS-XE system messages — format and catalog

How Cisco structures syslog messages, and what the 17.18 catalog actually
contains. Relevant to [ingesters/syslog.py](../../../observability/ingesters/syslog.py),
which today handles RFC 3164/5424 plus FortiGate `key=value` and Palo Alto CSV —
Cisco messages fall through to the generic path.

**Source:** *System Message Guide for Cisco IOS XE 17.18.x*, extracted locally
with `pdftotext`. **Retrieved:** 2026-07-29.

---

## 1. Message structure

```
%FACILITY-SUBFACILITY-SEVERITY-MNEMONIC: Message-text
```

| Part | Meaning |
|---|---|
| `FACILITY` | Two or more uppercase letters identifying a hardware device, protocol, or software module |
| `SUBFACILITY` | Optional, present on some messages |
| `SEVERITY` | Single digit 0–7; **lower is more serious** |
| `MNEMONIC` | Uniquely identifies the message within the facility |
| `Message-text` | Description, with variable fields in square brackets |

Example: `%LINK-2-BADVCALL: Interface [chars], undefined entry point`

Line-card variant, where the real message is prefixed:

```
%CARD-SEVERITY-MSG:SLOT %FACILITY-SEVERITY-MNEMONIC: Message-text
```

`CARD` is the card type, `MSG` is a literal, `SLOT` is `SLOT` plus a number. A
parser keying on the *first* `%…-N-…` token would pick up the card wrapper
rather than the real facility on these.

## 1.1 Variable-field placeholders

Message text in the catalog uses typed placeholders where runtime values appear:

| Placeholder | Type | | Placeholder | Type |
|---|---|---|---|---|
| `[chars]` | Character string | | `[dec]` | Decimal number |
| `[char]` | Single character | | `[hex]` | Hexadecimal number |
| `[int]` | Integer | | `[inet]` | IP address (`10.0.2.16`) |
| `[enet]` | Ethernet address (`0000.FEED.00C0`) | | `[node]` | Address or node name |

**Why this matters for the event model:** the `FACILITY-SEVERITY-MNEMONIC`
triple is a *stable* identifier while the rendered text varies per occurrence.
Deduplicating or grouping on the full message text would treat every occurrence
as distinct; the mnemonic is the part that identifies "the same kind of event".
That is the same distinction `evidence.dedup_key` already makes elsewhere — see
[architecture.md](../../architecture.md) §2.

---

## 2. Severity levels

Cisco's levels are identical to syslog's, so the existing PRI-derived severity
in the parser is correct and needs no Cisco-specific mapping.

| Level | Name | Meaning |
|---|---|---|
| 0 | emergency | System unusable |
| 1 | alert | Immediate action needed |
| 2 | critical | Critical condition |
| 3 | error | Error condition |
| 4 | warning | Warning condition |
| 5 | notification | Normal but significant |
| 6 | informational | Informational only |
| 7 | debugging | Debug output |

This is the same 0–7 scale that `HIGH_SEVERITY_LOG_001` thresholds on (≤ 3) and
that the correlator uses for its standalone-event exception
([live-flows-and-siem.md](../../live-flows-and-siem.md) §4.5). No conversion
needed.

**Default logging level is 7 (debugging) to console.** A device left at default
and pointed at SentinelNet will send a lot of noise.

---

## 3. What the 17.18 catalog contains

Measured from the extracted text:

- **2,507** distinct `FACILITY-SEVERITY-MNEMONIC` identifiers
- **315** distinct facilities
- **516** of them at severity 0–2

Largest facilities: `CMRP` (199), `DMI` (115), `CMCC` (101), `VMAN` (72),
`IM` (72), `CMRP_PFU` (57), `APMGR_TRACE_MESSAGE` (52), `AUTO_UPGRADE` (38),
`INSTALL` (35), `BOOT` (32), `STACKMGR` (23).

### Scope warning

**This guide covers platform and infrastructure messages, not classic L2/L3
events.** Verified by search: it contains **no** `LINEPROTO-*`, `SPANTREE-*`,
`MAC_MOVE`/`MACFLAP`, or `ERRDISABLE-*` entries, and only one `LINK-*`
(`LINK-2-BADVCALL`, quoted as a format example).

So the messages most relevant to SentinelNet's interface rules —
`%LINK-3-UPDOWN` and `%LINEPROTO-5-UPDOWN` — are **not** documented here. Those
live in the per-technology system message references. If interface state is ever
to be driven from syslog rather than from SNMP/REST snapshots, that is the
document to obtain.

---

## 4. Message groups worth wiring up

Two clusters in this catalog map onto facts SentinelNet already models.

### Stack events (`STACKMGR`, 23 messages)

Relevant wherever switches are stacked, which is the common access-layer
deployment.

| Severity | Messages |
|---|---|
| 1 (alert) | `RELOAD`, `RELOAD_REQUEST`, `FATAL_ERR`, `STACK_MERGE_IGNORE`, `DUAL_ACTIVE_CFG_MSG`, `EPA_MISMATCH`, `LIC_MISMATCH` |
| 4 (warning) | `SWITCH_ADDED`, `SWITCH_REMOVED` |
| 6 (info) | `ACTIVE_ELECTED`, `STANDBY_ELECTED`, `CHASSIS_ADDED`, `CHASSIS_REMOVED`, `CHASSIS_REMOVED_KA`, `KA_MISSED`, `STACK_LINK_CHANGE`, `SWITCH_READY`, `DISC_START`, `DISC_DONE` |

`STACKMGR-6-CHASSIS_REMOVED_KA` and `KA_MISSED` are stack-keepalive loss — a
member leaving the stack. That is a topology change the platform currently only
learns about at the next triage.

### Environment and power (`CMRP_ENVMON`, `CMRP_PFU`)

`CMRP_PFU-1-PFU_FAN_FAILED`, `CMRP_PFU-1-PFU_NO_FAN`,
`CMRP_PFU-2-FAN_POLICY_CRITICAL`, `CMRP_PFU-3-PEM_STATUS`,
`CMRP_ENVMON-3-TEMP_WARN_CRITICAL`, `CMRP_ENVMON-3-TEMP_SYS_SHUTDOWN_PENDING`.

`TEMP_SYS_SHUTDOWN_PENDING` is a device announcing it is about to power itself
off. At severity 3 it already trips `HIGH_SEVERITY_LOG_001`, so it produces
evidence today — but as a generic high-severity log, without the meaning.

---

## 5. Gaps this leaves

- The parser does not extract `FACILITY` or `MNEMONIC` from Cisco messages; they
  stay inside the raw message text. Adding that would give a stable event
  identity for Cisco sources, matching what `fieldmap.kv()` already does for
  FortiGate.
- The catalog also carries a **Component** and a **Recommended Action** column
  per message. That is precisely the shape of the knowledge base described in
  [principles.md](../../principles.md) §11 — a mapping from observed event to
  suggested investigation, already written by the vendor.
- Neither is implemented. Recorded here as available raw material, not as a plan.
