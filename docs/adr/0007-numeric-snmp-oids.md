# ADR-0007 — SNMP uses numeric OIDs, no MIB resolution

**Status:** Accepted
**Date:** 2026-07-27

## Context

Per-device state only reached the reasoning engine from FortiGates with a
configured REST token. Switches — the majority of any network — contributed
nothing, so rules like `IFACE_DOWN_001` and `DEVICE_LOAD_001` had almost no
input. SNMP is the vendor-agnostic way to close that gap.

The usual approach is to compile MIB files and reference symbolic names
(`ifOperStatus`), which requires shipping and loading MIBs at runtime.

## Decision

Query **numeric OIDs** directly, no MIB resolution:

- system scalars from RFC1213 (`1.3.6.1.2.1.1.*`);
- interface columns from IF-MIB;
- CPU/memory from CISCO-PROCESS-MIB, HOST-RESOURCES-MIB, CISCO-MEMORY-POOL-MIB,
  tried in order with a documented fallback to the long-deprecated
  OLD-CISCO-CPU-MIB where it's the only thing a device answers.

`ifName` is the table key, not `ifIndex`.

**Read-only, v2c only.** No SET operations.

## Consequences

- No MIB files to ship, so PyInstaller doesn't have to bundle them and there's
  no runtime MIB compiler to fail inside a frozen exe. This is the deciding
  factor, not elegance.
- The OID list is explicit in the source, so what's collected is obvious from
  reading it.
- `ifName` is the name the engineer sees on the device; `ifIndex` changes across
  reboots on several vendors and would silently re-key history.
- No SET means a compromised community cannot modify a device. The community
  still travels in clear text — a v2c limitation, not an implementation one:
  management network only, and the note is on the device record.
- Cost: adding a new metric means finding its OID by hand. Acceptable at the
  current rate of additions.
- Cost: vendor-specific OIDs are guesswork on devices we can't test against.
  Hence the fallback chain and per-device best-effort behaviour.

## Alternatives rejected

**MIB compilation with pysnmp's resolver.** Symbolic names are nicer to read,
but it means bundling MIBs, resolving at runtime, and debugging why the frozen
exe can't find them. Cost is paid at every build for a benefit paid once at
write time.

**SNMPv3.** Better security (auth + privacy), but per-device credential
management that the inventory doesn't model yet. Read-only v2c on a management
network is the proportionate answer today.

**Per-vendor CLI parsing instead of SNMP.** That's what backup/triage already
does, and it's the thing SNMP is here to avoid: it means a parser per vendor per
command, drifting with every firmware release.

## When to revisit

If SNMP data ever needs to cross an untrusted network, v3 stops being optional.
If the OID list outgrows hand-maintenance, a per-vendor OID table is the next
step — still numeric.
