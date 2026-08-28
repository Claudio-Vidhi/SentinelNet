# Cisco IPv4 ACLs (IOS XE 17.18.x, Catalyst 9200)

Distilled from *Security Configuration Guide, Cisco IOS XE 17.18.x (Catalyst
9200 Switches)*, chapter 21 "IPv4 ACLs". These are notes taken from Cisco's
documentation, not a description of this codebase.

17.18 is likely **ahead of any deployed train**. Statements below that are
version- or platform-sensitive are flagged inline. Everything in
[§1](#1-evaluation-semantics) is stable across every IOS release SentinelNet is
likely to meet; the rest is not.

Consumers in this repo: `services/policy_test/ios.py` (parser),
`services/policy_test/engine.py` (evaluation), `services/policy_test/findings.py`
(defect detection), `ai/config_analyzer.py`, `services/netsec_audit/`.

---

## 1. Evaluation semantics

The rules the whole validation subsystem rests on:

1. An ACL is an **ordered** list of ACEs. Packets are tested one by one and
   **the first match decides** — permit or deny. Testing stops there, so ACE
   order is significant.
2. If no ACE matches, the packet is **denied**. Every ACL carries an implicit
   `deny ip any any` at the end, standard and extended alike.
3. **An ACL applied to an interface but never defined permits all packets.**
   The device behaves as if nothing were applied. Stated twice in the guide —
   for router ACLs and for port ACLs — and it is the single most dangerous
   default to model wrongly: an unresolved binding is *permit-all*, not
   deny-all.
4. Inbound: the ACL is checked on receipt, and a reject discards the packet
   before any routing. Outbound: the packet is received and routed to the
   egress interface first, then checked, and a reject discards it there.

## 2. ACL kinds and where they attach

| Kind | Attaches to | Direction | Matches |
|---|---|---|---|
| Port ACL | L2 physical + EtherChannel interfaces (not member ports) | see caveat | standard IP, extended IP, or MAC extended |
| Router ACL | SVIs, L3 physical, L3 EtherChannel | in and out, **one each** | standard or extended IPv4 |
| VLAN map (VACL) | a VLAN, via `vlan filter` | none — directionless | via `match ip/mac address <acl>` |

**Direction caveat for port ACLs.** The guide contradicts itself: the Port ACLs
section says they "can be applied to the interface in inbound and outbound
direction", the paragraph under the topology figure says "Port ACLs can only be
applied to Layer 2 interfaces in the inbound direction", and the `mac
access-group` procedure says "Port ACLs are supported in the outbound and
inbound directions". Treat outbound port ACLs as **platform- and
release-dependent**; verify on the running box before asserting anything about
them.

Other placement rules:

- Only **one IP access list and one MAC access list** per L2 interface.
  Applying a new one of the same type **replaces** the previous one silently.
- `mac access-group` is valid only on a physical L2 interface — never on an
  EtherChannel port-channel.
- ACLs **cannot** be configured on management ports.
- ACLs support only Layer 3 interfaces (routed and VLAN interfaces) and
  sub-interfaces — plus L2 interfaces, for port ACLs.
- An ACL on an L3 interface of a switch with **routing disabled** filters only
  CPU-bound traffic (SNMP, Telnet, web).
- A port ACL on a trunk filters **all VLANs** on that trunk; on a voice-VLAN
  port it filters both data and voice VLANs.
- A port ACL on an L2 member of a VLAN **takes precedence** over the SVI's
  input router ACL and over the VLAN map.

## 3. Precedence when several kinds coexist

- **Ingress**: port ACL → VLAN map → router ACL (greatest to least).
- **Egress**: router ACL → VLAN map → port ACL.

A packet filtered by a higher-precedence ACL is **not** re-tested by the lower
ones. Consequences worth modelling:

- Input port ACL + VLAN map: ports carrying a port ACL are filtered by it,
  every other port by the VLAN map.
- VLAN map + router ACL on the same SVI: a packet matching a **VLAN-map deny
  clause is denied regardless of the router ACL**.
- Packets denied by a VLAN map are **not logged**, even when the router ACL
  asked for logging.

## 4. VLAN maps — the inverted match

VLAN maps do not use `permit`/`deny`. Each entry has a `match {ip|mac} address`
clause plus `action {forward|drop}`. Inside the ACL named by the match clause:

- a **permit** counts as a **match**;
- a **deny** means **no match**.

Defaults invert on the presence of a match clause for the packet's type:

| Map contains, for that packet type (IP or MAC) | Packet matches no entry |
|---|---|
| at least one match clause | **drop** |
| no match clause | **forward** |

Also: entries are ordered and tested top-down; only one map per VLAN; maps have
no direction (to filter a direction, write directional source/destination into
the ACL); logging is unsupported; and a map that cannot be programmed in
hardware causes **all packets in that VLAN to be dropped**.

## 5. Syntax the parser has to read

### 5.1 Numbers decide the type

| Range | Type | Supported on this platform |
|---|---|---|
| 1–99 | IP standard | yes |
| 100–199 | IP extended | yes |
| 1300–1999 | IP standard (expanded) | yes |
| 2000–2699 | IP extended (expanded) | yes |
| every other band (200–1299) | protocol-type, DECnet, XNS, AppleTalk, MAC, IPX… | **no** |

A named ACL's *name* may itself be a number in the supported range. A standard
and an extended ACL **cannot share a name**.

### 5.2 Address specs

- `any` — `0.0.0.0 255.255.255.255`
- `host <ip>` — `<ip> 0.0.0.0`
- `<ip> <wildcard>` — wildcard bits, **not** a netmask, and **not required to
  be contiguous**
- in a standard ACL, an omitted mask means `0.0.0.0`, i.e. a host match

### 5.3 Extended ACE grammar

```
{permit|deny} <proto> <src> [<src-port-op>] <dst> [<dst-port-op>]
    [established] [precedence <p>] [tos <t>] [dscp <d>] [fragments]
    [time-range <name>] [log|log-input]
```

- Port operators: `eq`, `gt`, `lt`, `neq`, `range <lo> <hi>`. Port as a decimal
  0–65535 or a well-known name. A source operator sits **after the source
  wildcard**, a destination operator **after the destination wildcard** —
  position is the only thing that distinguishes them.
- `established` (TCP only) matches `ack` **or** `rst`. Individual flags:
  `ack fin psh rst syn urg`.
- ICMP adds `[icmp-type [icmp-code] | icmp-message]`; IGMP adds `[igmp-type]`
  (0–15, or `dvmrp host-query host-report pim trace`).
- `dscp` is **mutually exclusive** with `tos`/`precedence`.
- Named protocols accepted: `ahp esp eigrp gre icmp igmp ip ipinip nos ospf
  pcp pim tcp udp`.
- `remark <text>` carries no matching semantics; 100 characters per line.

### 5.4 Bindings

| Command | Context | Note |
|---|---|---|
| `ip access-group {num or name} {in\|out}` | interface | router or port ACL |
| `mac access-group <name> {in\|out}` | physical L2 interface | non-IP traffic |
| `access-class <num> {in\|out}` | `line console` / `line vty` | **numbered only** — named ACLs are rejected on lines |
| `vlan filter <map> vlan-list <list>` | global | list may be `22`, `10-22`, or `12,22,30` |
| `ip access-group …` inside `template <name>`, then `source template <name>` | global | 17.5.1+; **the binding is not in the interface block** |

## 6. Things that silently change what an operator sees

- **`show ip access-lists` hit counters do not count hardware-switched
  packets.** ACL processing happens in hardware; the counter reflects only what
  reached the CPU. A zero counter is therefore **not** evidence that a rule
  never fired. Hardware counters need `show platform software fed switch
  {num|active|standby} acl counters hardware`. Any "never hit / dead rule"
  claim built on `show ip access-lists` output is unsound.
- **Time ranges** make an ACE conditionally inactive, and `show access-lists`
  marks it `(inactive)`. A config-only reading cannot know whether a
  time-ranged ACE is live now. Time ranges follow the system clock, so NTP is
  a precondition for them meaning anything.
- **Sequence numbers**: from IOS XE Bengaluru 17.5.1, `show ip access-list
  <name>` and `show run section <name>` print ACEs in ascending sequence order.
  Numbered ACLs are **append-only** — no reordering, no selective removal;
  named ACLs allow `no permit …` / `no deny …`.
- **Logging** is rate-limited and lossy by design: the first packet logs
  immediately, then 5-minute aggregation, and messages are dropped when there
  are too many. Cisco explicitly says not to use it as a counting source.
  Lines start with `%SEC-6-IPACCESSLOG*`: `…LOGS` (standard), `…LOGDP` (with
  ICMP type/code), `…LOGP` (with ports). `log-input` adds the ingress
  interface and source MAC; `log` does not.
- Logging is unsupported for **uRPF ACLs**, for **VLAN maps**, in **SVL**
  deployments, and in the **egress** direction for control-plane-generated
  packets.
- Adding `log` to a permit ACE still switches the packet in hardware; only a
  copy goes to the CPU. `log` and ICMP-unreachable generation are the two
  things that punt router-ACL traffic to the CPU.
- If the hardware runs out of room for an ACL, **all packets on that interface
  are dropped**; scoped to the VLAN and the device when the failure is an
  out-of-resource condition on one stack member.

## 7. Fragments

Only the first fragment carries L4 information. For the remaining fragments the
matching rules change:

- a **permit** ACE that tests only L3 (including protocol) **matches** any
  fragment, regardless of the missing L4 data;
- a **deny** ACE that tests L4 **never matches** a fragment lacking L4 data;
- TCP ACEs with L4 operators drop fragmented packets per RFC 1858.

Net effect Cisco spells out: denying the first fragment is enough to break
reassembly, but the later fragments may still be permitted and will consume
bandwidth and target resources on the way.

## 8. Unsupported

Non-IP protocol ACLs; IP accounting; dynamic, reflexive and firewall access
lists; the ToS *minimize-monetary-cost* bit; TTL classification; ACL wildcards
in downstream client policy; `appletalk` as a MAC ACL match condition. ICMP
echo-reply **cannot** be filtered — every other ICMP type and code can.
Duplicate entries in a downloadable ACL are not auto-merged and make 802.1X
session authorization fail.

---

## 9. What SentinelNet implements today

Read against `services/policy_test/ios.py` and `services/policy_test/engine.py`:

| Doc fact | Implemented | Where |
|---|---|---|
| First match wins, order significant | yes | `engine._first_match` |
| Implicit deny at end | yes | `Step(matched="implicit deny")`, `RuleSet.default_action = "deny"` |
| Number ranges pick standard vs extended | yes, exactly the four supported bands | `ios.parse_ace_line` |
| `any` / `host` / `<ip> <wildcard>` | yes, non-contiguous wildcards included | `ios._consume_ip_spec`, `Cube` |
| Port operators `eq gt lt neq range` | yes | `ios._consume_port_spec` |
| `established` | yes | `FieldSet.established` |
| ICMP message type (`echo`, `echo-reply`, numeric) | yes | `ios._ICMP_TYPE_NAMES`, `FieldSet.icmp_types`, `Flow.icmp_type` |
| Every other trailing qualifier | recorded, never dropped | `ios._consume_trailing_qualifiers` → `FieldSet.narrowing_quals` |
| `remark` ignored | yes | `parse_ace_line` returns `None` |
| Named `standard`/`extended` blocks, numbered one-liners | yes | `parse_ios_config` block extractor |
| `ip access-group … in/out` on interfaces | yes | interface block reader |
| Undefined ACL bound to an interface ⇒ permit all | **verdict right, note wrong** | the ingress branch tests `acl_in_name in env.acls`, so an undefined ACL falls through to permit — which matches §1.3. The step note reads *"no inbound ACL bound"*, which is not what happened. |
| Object-group address/service references | partial — resolved when defined, `opaque` with a stated reason otherwise | `ios._opaque_rule` |

## 10. Known gaps, and whether they matter

Ordered by how wrong the answer gets if a real config uses the feature.

1. **VLAN maps are not parsed at all** (`vlan access-map`, `vlan filter`). A
   VLAN-map deny beats the router ACL (§3), so on a device that uses them the
   tracer can answer PERMIT for a flow the hardware drops. This is the one gap
   that produces a *confidently wrong* verdict rather than an incomplete one.
   The inverted permit-means-match semantics of §4 have to be honoured if it is
   ever implemented.
2. **Port ACLs and MAC ACLs are not parsed**, and the precedence order of §3 is
   not modelled — the engine evaluates a single router-ACL chain. Same failure
   shape as (1) on access ports.
3. **`access-class` on vty/console lines is not parsed.** Management-plane
   reachability is invisible to the tracer. Little effect on data-path answers,
   real effect on "can I still reach this box after the change".
4. **Interface templates** (`source template`) are not followed, so a binding
   configured in a template looks like no binding at all — which the engine
   reads as permit.
5. **`precedence` / `tos` / `dscp` / `fragments` / `time-range` / TCP flag bits
   are still not evaluated**, and neither is the ICMP *code*. They are no
   longer discarded, though: the ACE records them in
   `FieldSet.narrowing_quals`, which stops it claiming to cover a neighbour
   and makes a trace that reaches it answer UNKNOWN. Imprecise, not wrong.
6. **The fragment rules of §7 are not modelled.** Acceptable — the tracer
   answers about whole packets.

### The defect these two replaced

Until 0.7.1 every trailing qualifier was thrown away and the rule was recorded
as fully understood. Since each one *narrows* the ACE on the device, dropping
it **widened** the rule here, and a widened rule swallows its neighbours. On a
real config that produced:

```
10 permit icmp <net>/24 any        echo-reply     → modelled as: icmp <net>/24 → any
20 permit icmp <net>/24 host <gw>  echo           → modelled as: icmp <net>/24 → <gw>
```

and a HIGH "rule 20 is shadowed by rule 10" on two ACEs that share no packet
at all: an echo request is type 8, an echo reply is type 0. Two false
positives on one device, both endorsed by their own witness proof, because the
witness is built from the same widened model the finding came from.

The lesson is the general one, not the ICMP one: **a qualifier that is parsed
but not modelled must be recorded, never dropped.** Silence there does not
lose precision, it manufactures confident false findings.
