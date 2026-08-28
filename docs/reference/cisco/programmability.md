# IOS-XE NETCONF / RESTCONF — operational reference

What has to be true on a Catalyst before
[mac_collector.py](../../../collectors/mac_collector.py) can reach it over
NETCONF or RESTCONF, and how to check each condition from the device CLI.

**Source:** *Programmability Command Reference, Cisco IOS XE 17.18.x*
(first published 2025-07-31), extracted locally with `pdftotext`.
**Retrieved:** 2026-07-29.

> **Version caveat.** This is the 17.18 reference, which is likely ahead of any
> deployed train. Every command cited below carries its *Command History* line,
> recording the release that introduced it — check that against the running
> software before relying on it. Behaviour described without a history line
> should be confirmed on the device.

---

## 1. What the collectors need

| Transport | Code | Default port | Depends on |
|---|---|---|---|
| NETCONF | `collect_via_netconf()` | 830 | `ncsshd` running, SSH algorithm overlap |
| RESTCONF | `collect_via_restconf()` | 443 | `nginx` running, no blocking ACL |
| CLI | `collect_via_cli()` | 22 | always available — the fallback |

The fallback order is NETCONF → RESTCONF → CLI. Everything below is about why
the first two fail, since a failure is silent: the chain just falls through to
CLI and nobody notices the fast path is dead.

---

## 2. Is NETCONF actually enabled?

```
Device# show netconf-yang status

netconf-yang: enabled
netconf-yang candidate-datastore: disabled
netconf-yang side-effect-sync: enabled
netconf-yang ssh port: 830
netconf-yang turbocli: disabled
Hostkey Algorithms: rsa-sha2-256,rsa-sha2-512,ssh-rsa
Encryption Algorithms: aes128-ctr,aes192-ctr,aes256-ctr
MAC Algorithms: hmac-sha2-256,hmac-sha2-512,hmac-sha1
KEX Algorithms: diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,
ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group16-sha512
```

*(Introduced in IOS-XE Denali 16.3.1 — present on any 16.3+ train.)*

**The algorithm lists are the part that matters.** A NETCONF failure that looks
like a timeout or a handshake error is usually an algorithm mismatch between
what the device advertises and what paramiko/ncclient offers — not a missing
YANG model. Check these lists before assuming the model is absent.

The port is configurable and is **not guaranteed to be 830**:

| Command | Effect |
|---|---|
| `netconf-yang ssh port <n>` | Moves the NETCONF SSH listener |
| `netconf-yang ssh port disable` | Disables the dedicated port entirely |
| `netconf-yang ssh server algorithm {encryption\|hostkey\|kex\|mac}` | Narrows the advertised algorithms — the usual cause of a mismatch |

`collect_via_netconf()` takes `port=830` as a default parameter, so a device
with a moved port needs it passed explicitly.

---

## 3. Are the supporting processes running?

```
Device# show platform software yang-management process

confd           : Running      ← configuration daemon
nesd            : Running      ← network element synchronizer
syncfd          : Running      ← sync-from daemon
ncsshd          : Running      ← NETCONF SSH daemon
dmiauthd        : Running      ← DMI authentication
vtyserverutild  : Running
opdatamgrd      : Running      ← operational data manager
nginx           : Running      ← serves RESTCONF
ndbmand         : Running
```

*(Introduced in IOS-XE Everest 16.3.1.)*

Two entries map directly onto the collectors:

- **`ncsshd` not running** → NETCONF is unreachable regardless of configuration.
- **`nginx` not running** → RESTCONF is unreachable. Same symptom, different
  daemon.

`opdatamgrd` is what serves *operational* data — which is exactly what
`Cisco-IOS-XE-matm-oper` is. If it is down, the model exists but returns
nothing.

---

## 4. RESTCONF access control

```
Device(config)# ip access-list standard ipv4_acl1_permit
Device(config-std-nacl)#  permit 192.168.255.0 0.0.0.255
Device(config-std-nacl)#  deny any
Device(config)# restconf ipv4 access-list name ipv4_acl1_permit
```

*(Introduced in IOS-XE Gibraltar 16.11.1.)*

**Default is permissive** — client connections are allowed when no ACL is
configured. But where an ACL exists and the SentinelNet host is not in it, the
collector gets a connection failure that is indistinguishable from "RESTCONF is
off". Worth checking before debugging the model path.

Cisco's own note: *"You can use an access-list name that is not defined"* — a
typo in the ACL name silently produces a config that blocks nothing, or
everything, depending on the list. Do not assume a configured ACL is a working
ACL.

---

## 5. Locking

Read operations are permitted by any NETCONF/RESTCONF session while a global
lock is held; writes are not. Since both collectors are **read-only**, an active
configuration lock elsewhere on the device does not block MAC-table collection.

---

## 6. What this document does not answer

The original question was *which IOS-XE train exposes
`Cisco-IOS-XE-matm-oper`*. **This PDF does not answer it.** It is a command
reference — it documents CLI syntax, not YANG model availability per release.
Model availability lives in Cisco's YANG model repository
(`github.com/YangModels/yang`, `vendor/cisco/xe/<release>/`), not here.

The cheaper answer remains a device query:

```
Device# show netconf-yang capabilities | include matm
```

That reports what the device in front of you actually supports, which is the
thing the collector needs to know.

---

## 7. Diagnostic order for a failed fast path

When MAC collection silently falls back to CLI:

1. `show platform software yang-management process` — is `ncsshd` / `nginx` up?
2. `show netconf-yang status` — enabled? which port? which algorithms?
3. `show netconf-yang capabilities | include matm` — is the model there?
4. `show running-config | include restconf` — is an ACL blocking the host?
5. Only then suspect the collector.
