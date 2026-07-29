# Catalyst 9000 — SNMP MIB support

Which MIBs the SNMP poller can rely on, per platform. This exists because
[snmp_poller.py](../../../observability/ingesters/snmp_poller.py) queries numeric
OIDs with no MIB resolution ([ADR-0007](../../adr/0007-numeric-snmp-oids.md)), so
"does this platform actually implement that OID" is not answerable from the code.

**Source:** Cisco's published per-platform support lists at
`https://cisco.github.io/cisco-mibs/supportlists/<platform>/<PLATFORM>.html`.
**Retrieved:** 2026-07-29. **Method:** pages downloaded and grepped directly —
no model in the extraction path.

Re-check after a major IOS-XE train change. Cisco's pages carry no version
stamp, so treat them as "current" rather than pinned.

---

## 1. Support matrix

| MIB | 9200 | 9300 | 9400 | 9500 |
|---|:---:|:---:|:---:|:---:|
| `CISCO-PROCESS-MIB` | ✅ | ✅ | ✅ | ✅ |
| `CISCO-MEMORY-POOL-MIB` | ✅ | ✅ | ✅ | ✅ |
| `CISCO-ENHANCED-MEMPOOL-MIB` | ❌ | ✅ | ✅ | ✅ |
| `HOST-RESOURCES-MIB` | ❌ | ❌ | ❌ | ❌ |
| `OLD-CISCO-CPU-MIB` | ✅ | ✅ | ✅ | ✅ |
| `IF-MIB` | ✅ | ✅ | ✅ | ✅ |
| `LLDP-MIB` | ✅ | ✅ | ✅ | ✅ |
| `ENTITY-MIB` | ✅ | ✅ | ✅ | ✅ |
| `BRIDGE-MIB` | ✅ | ✅ | ✅ | ✅ |
| `CISCO-CDP-MIB` | ❌ | ❌ | ❌ | ❌ |
| `CISCO-VTP-MIB` | ❌ | ❌ | ❌ | ❌ |

Total MIBs listed: 9200 → 96 · 9300 → 118 · 9400 → 133 · 9500 → 118.

Cisco's own disclaimer applies: *"not all objects are supported in all of the
listed MIBs."* Presence in the list means the MIB is implemented, not that every
object in it returns a value.

The CAT9600 support list linked from Cisco's index returns **404**. Not covered
here.

---

## 2. Verdict on the OIDs the poller uses

### CPU — `_CPU_OIDS`, tried in order

| # | OID | MIB | Catalyst 9000 |
|---|---|---|---|
| 1 | `1.3.6.1.4.1.9.9.109.1.1.1.1.8` | `CISCO-PROCESS-MIB` cpmCPUTotal5minRev | ✅ **works — this is the one that answers** |
| 2 | `1.3.6.1.2.1.25.3.3.1.2` | `HOST-RESOURCES-MIB` hrProcessorLoad | ❌ **dead branch on every 9000 platform** |
| 3 | `1.3.6.1.4.1.9.2.1.58` | `OLD-CISCO-CPU-MIB` avgBusy5 | ✅ still implemented, despite being deprecated |

The chain is correct as written: entry 1 answers on all four platforms, so the
poller gets its value on the first try.

**Entry 2 never answers on Catalyst 9000.** It is not harmful — it is only
reached when entry 1 is silent — but it is dead weight on this platform family.
It stays justified for non-Cisco or Linux-based devices, which is why it was
added; the code comment should say so rather than implying it is a Cisco
fallback.

**Entry 3 is a better fallback than its comment suggests.** The code notes it is
"deprecated 20 years ago, but the only one CML's IOL/IOSv answer". It is in fact
still implemented on current 9200/9300/9400/9500 hardware — so the lab fallback
is also a valid production fallback.

### Memory — `_MEM_USED_OID` / `_MEM_FREE_OID`

Currently `1.3.6.1.4.1.9.9.48.1.1.1.5` and `.6` — `CISCO-MEMORY-POOL-MIB`.

**This is the correct choice, and it should not be "modernized".**
`CISCO-ENHANCED-MEMPOOL-MIB` looks like the newer, better option and is present
on 9300/9400/9500 — but it is **absent on the 9200**. Switching to it would
silently break memory reporting on the entry-level platform, which is exactly
where it is most likely to be deployed in access closets.

Keep `CISCO-MEMORY-POOL-MIB`. If per-pool granularity is ever needed, the
enhanced MIB has to be a 9200-aware fallback, not a replacement.

### Interfaces

`IF-MIB` is supported everywhere, so the interface walk (`ifName`, `ifAdminStatus`,
`ifOperStatus`, counters) is safe across the family. `ifName` as the table key
remains correct — see [ADR-0007](../../adr/0007-numeric-snmp-oids.md).

---

## 3. What this does not cover

- **`CISCO-CDP-MIB` and `CISCO-VTP-MIB` are absent** from all four support lists.
  This has no impact: SentinelNet reads CDP/LLDP neighbours and the VTP domain
  from CLI output captured in the device backup
  ([collectors.md](../../collectors.md) §9), never over SNMP.
- **Catalyst 3850 and 2960/2960X** are not covered by these lists. The 3850 is an
  IOS-XE platform and so is closest to the 9000 family; the 2960 line runs
  classic IOS and has its own MIB set. Neither has been verified against Cisco's
  published lists — check the corresponding support list before assuming an OID
  answers there.
- **Per-object support.** These lists are MIB-level. An OID inside a supported
  MIB can still return `NoSuchInstance`, which the poller already handles.

---

## 4. Action items this produced

None applied — this document records findings only.

1. Correct the comment on `_CPU_OIDS[1]`: it is a non-Cisco fallback, not a
   Cisco one. It never answers on Catalyst 9000.
2. Correct the comment on `_CPU_OIDS[2]`: still implemented on current hardware,
   not lab-only.
3. Add a note next to `_MEM_USED_OID` warning against switching to
   `CISCO-ENHANCED-MEMPOOL-MIB` because of the 9200 gap.
