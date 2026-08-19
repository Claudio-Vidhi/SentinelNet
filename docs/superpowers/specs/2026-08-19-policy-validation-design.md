# Policy & Route Validation — design

Date: 2026-08-19
Status: approved design, not yet implemented

> Example addresses are RFC 5737 (`192.0.2.x`, `198.51.100.x`), as required by
> `CLAUDE.md` §"Protect real data".

## 1. Problem

The product already parses ACLs, static routes and firewall policies out of
config backups, and renders them as tables. A table of forty ACEs does not
answer the question an operator actually has:

> "Can this host reach that server on 443, and if not, which line stops it?"

Reading the answer off the tables requires holding wildcard masks, object
groups, rule order and the route table in your head at once. That is exactly
the kind of work a machine should do.

## 2. Scope

**In scope**

* Offline evaluation from stored config backups only. No live device queries.
* One device per evaluation. The result is shaped so a multi-hop path walker
  can be added later without reshaping the data.
* Cisco IOS / IOS-XE: named and numbered ACLs, connected and static routes.
* FortiOS: firewall policies, address objects, address groups, custom and
  builtin services, interfaces and zones.
* Three outputs from one engine: interactive tracer, generated example traffic
  per rule, static findings.

**Explicitly out of scope for v1**

* Live device lookups (`show ip route`, `diagnose firewall iprope lookup`).
  The user ruled these out: the verdict must be derivable from a backup alone.
* PAN-OS. `fw_analyzers/panos.py` exists and the model is vendor-neutral, so
  it is a later addition, not a redesign.
* Multi-hop path evaluation across devices.
* NAT translation of the traced flow. NAT is *reported* when a matched policy
  has it enabled, but the post-NAT packet is not re-evaluated.
* Dynamic routing protocols (see §7).
* IPv6. The cube model is width-agnostic but v1 ships IPv4 only.

## 3. Core model — one matcher, three readers

The tracer, the example generator and the findings list are not three engines.
Each rule is a **set of packets**, described field by field. Everything else is
a way of reading that set.

| Reader | Operation on the set |
| :--- | :--- |
| Tracer | first rule whose set contains the flow |
| Examples | pick a representative point inside the set, and one just outside |
| Findings | containment tests between two rules' sets |

Three engines would mean three places for the same matching bug to hide.

### 3.1 Field representation

* **IP fields** — a list of ternary cubes `(value: int, mask: int)`, where a
  1-bit in `mask` means "this bit is significant". Exact for CIDR, and also
  exact for the non-contiguous IOS wildcard masks (`0.0.255.0`) that a
  prefix-length representation silently corrupts.
* **Ports** — a list of closed integer intervals `(lo, hi)`. Covers
  `eq/gt/lt/range`; `neq` becomes two intervals.
* **Protocol** — a set of IP protocol numbers, or `ANY`.
* **Interface / zone** — a set of names, or `ANY`.

Chosen over BDD / header-space analysis (exact under arbitrary unions, but
several hundred lines and a class of problem that a forty-line ACL does not
have) and over packet sampling (cheap, but an engine that answers "probably
permit" is an engine nobody trusts).

### 3.2 Declared ceiling

Shadow detection is a **single-rule superset test**: rule N is reported
shadowed only when one earlier rule fully covers it. "Rules 3, 7 and 11
together cover rule 14" is not detected, because exact multi-rule subtraction
on ternary cubes blows up combinatorially.

Deliberate ceiling, marked in the code with a `ponytail:` comment naming the
upgrade path (BDD). Not a bug to be filed.

## 4. Structure

Follows the `services/netsec_audit/` precedent: a package under `services/`
with a pure model, per-vendor front ends, and readers on top.

```
services/policy_test/
  model.py     Flow, Cube, FieldSet, Rule, RuleSet, Verdict, Trace, Step
  ios.py       ACE parser + connected/static route table -> RuleSet
  fortios.py   policy + address/addrgrp/service resolution -> RuleSet
  builtins.py  FortiOS factory objects absent from every backup (see §6.2)
  engine.py    evaluate(RuleSet, Flow) -> Trace
  examples.py  RuleSet -> per-rule matching and near-miss flows
  findings.py  shadowed / unreachable / any-any / route-to-nowhere
routers/policy_test.py       API, tenant-scoped
static/js/policy-test.js     dashboard tab
ai/mcp_server.py             +2 tools
```

`model.py`, `engine.py`, `examples.py` and `findings.py` are pure — no I/O, no
imports from `services` or `routers`. Same property as `analyze_config`, and
the reason the tests need no fixtures beyond text.

## 5. Evaluation sequence — resolved open question

**Decision: the tracer models the full on-device chain, not a single ACL.**

A packet crossing an L3 switch meets the ingress ACL, then the route lookup,
then the egress ACL. Evaluating one ACL in isolation answers a question the
operator did not ask. The chain is cheap to build because the bindings are
already parsed: `iface["acl_in"]` / `iface["acl_out"]` land in `acl_refs` with
`where="interface"` at `ai/config_analyzer.py:302`, and each interface already
carries its IP.

IOS chain:

1. **Ingress ACL** — the ACL bound `in` on the ingress interface.
2. **Route lookup** — longest-prefix match over connected + static routes,
   yielding the egress interface and next hop.
3. **Egress ACL** — the ACL bound `out` on that egress interface.

FortiOS chain: route lookup determines the egress interface, then the policy
list is walked in sequence order with `srcintf`/`dstintf` matched against
ingress and egress. Disabled policies (`set status disable`) are skipped but
reported as skipped, never silently.

**Ingress interface** is an optional input. When omitted it is derived from the
source IP's connected subnet. When that fails, every bound ACL is evaluated
independently and the result says so — it does not guess.

## 6. Two gaps this exposes

### 6.1 IOS ACEs are raw text today

`ai/config_analyzer.py:376` stores
`{"seq", "action", "text": "permit tcp any host 192.0.2.10 eq 443"}`. Nothing
downstream can match against a string.

`ios.py` adds a real ACE parser handling: protocol (name or number),
`any` / `host X` / `A.B.C.D wildcard`, `object-group`, port operators
`eq gt lt neq range`, `established`, ICMP types, `log` / `log-input` suffixes,
and the `remark` lines that must be skipped rather than parsed as rules.

The existing `text` field is left exactly as it is. The parser adds a parallel
structured form; nothing that reads `text` today changes behaviour.

Unparseable ACE → the rule enters the set as **opaque**: it matches nothing and
blocks no verdict, but the trace lists it, so a tracer answer is never quietly
computed over a rule the parser could not read.

### 6.2 FortiOS builtin objects are not in the backup

`set service "HTTPS"` and `set dstaddr "all"` reference factory objects that a
`show full-configuration` does not print. Resolving them against the config
alone yields nothing, and treating nothing as an empty set would turn every
such policy into a silent non-match.

`builtins.py` ships a static table of the FortiOS default services (`ALL`,
`ALL_TCP`, `ALL_UDP`, `ALL_ICMP`, `HTTP`, `HTTPS`, `SSH`, `PING`, `DNS`, `SMTP`,
`FTP`, `NTP`, `SNMP`, `RDP`, `SYSLOG`, `IKE`, …) and the default addresses
(`all`, `none`).

Anything still unresolved after config plus builtins renders as **UNKNOWN**,
never as `deny`. Same doctrine as `services/vlan_routing.py`: *ignoto non è
assente* — "we could not look" and "there is nothing there" are different
answers and must not be collapsed. ISDB / internet-service objects and FQDN
address objects fall in this class by construction.

## 7. Routes, honestly

Longest-prefix match over **connected (interface/SVI) plus static routes only**.
OSPF, EIGRP and BGP learned routes do not exist in a running-config.

A lookup that finds nothing returns `no_static_route` — explicitly not
`unreachable`. A tracer that answers "denied" when the box holds an OSPF route
it could not see is worse than one that admits the limit. When the config
contains a `router ospf|eigrp|bgp` block (already parsed into
`routing["protocols"]`), the trace carries a flag saying a dynamic protocol is
running and the route table is therefore incomplete by construction.

## 8. Verdict shape

Input:

```python
Flow(src_ip="192.0.2.50", dst_ip="198.51.100.9", proto="tcp",
     sport=None, dport=443, ingress_intf="Vlan10")
```

Output:

```python
Trace(
  verdict = "PERMIT" | "DENY" | "UNKNOWN",
  steps = [
    Step(kind="acl_in",  acl="GUEST_IN", matched="seq 30", action="permit"),
    Step(kind="route",   prefix="198.51.100.0/24", next_hop="192.0.2.1",
                         egress="Vlan20", source="static"),
    Step(kind="acl_out", acl=None, matched=None, action="permit",
                         note="no ACL bound outbound"),
  ],
  implicit_deny = False,
  dynamic_routing_present = True,
  unresolved = ["service 'CustomApp' referenced by policy 17 is not defined"],
)
```

`UNKNOWN` is a first-class verdict, not an error state. Returned whenever an
unresolved object or a missing route sits on the decision path — never
downgraded to `DENY` to make the output look decisive.

## 9. Example traffic generation — resolved open question

**Decision: pure core, optional real-address hint from the caller.**

`examples.py` stays pure and synthesises addresses inside each rule's cube. It
accepts an optional `hint_addresses` sequence; when a hint falls inside the
cube, it is preferred over a synthetic pick. The router passes recently seen
addresses from the ARP / client-map data, so the UI shows flows built from
hosts that actually exist while the module keeps zero I/O and stays testable
from text alone.

Per rule, the generator emits:

* one **matching** flow — a representative point inside the set,
* one **near-miss** flow — the same flow with the single most discriminating
  field moved just outside (one port off, one address outside the mask), which
  is what makes a complicated rule legible.

Everything committed to the repo — fixtures, docs, comments — uses RFC 5737
addresses and placeholder hostnames only. Real addresses appear at runtime, in
the UI, never in a tracked file.

## 10. Findings — resolved open question

**Decision: own findings list in the new tab. Reuse `netsec_audit`'s
message-key convention, not its rule pipeline.**

`services/netsec_audit/` is CIS-benchmark shaped: every outcome carries a
benchmark id, a severity and remediation guidance keyed to a control. "ACE at
seq 30 is shadowed by seq 10" is not a benchmark control, and inventing ids to
make it fit would corrupt the audit score.

What is reused is the *language* discipline from
`services/netsec_audit/model.py`: findings carry a message **key** plus params,
never a pre-rendered sentence, and rendering happens once at the API boundary.
An audit is a deliverable that must come out in Italian or English regardless
of the operator's UI language.

v1 findings:

* `shadowed` — an ACE or policy fully covered by a single earlier one
* `unreachable` — a rule after a covering `deny any any` / implicit deny
* `any_any` — permit with ANY source, ANY destination and ANY service
* `route_to_nowhere` — static route whose next hop lies in no connected subnet
* `unresolved_object` — a rule referencing an object defined nowhere

## 11. API and MCP surface

Router `routers/policy_test.py`, every endpoint tenant-scoped through
`assert_device_allowed` / `user_group_scope` from `routers/deps.py` — the same
guard the analyzer endpoints use. A device-IP route without that guard leaks
another customer's network.

```
POST /api/policy-test/{ip}/trace      body: Flow -> Trace
GET  /api/policy-test/{ip}/examples   -> per-rule matching + near-miss flows
GET  /api/policy-test/{ip}/findings   -> findings list
```

MCP tools in `ai/mcp_server.py`:

* `policy_trace(ip, src, dst, proto, dport, [ingress])` — so the assistant can
  answer reachability questions directly
* `policy_findings(ip)`

## 12. Frontend

New tab `tab-policy-test`, module `static/js/policy-test.js`. Three panels:
tracer form + trace rendering, per-rule examples browser, findings list.

Non-negotiable per the project's frontend rules, each learned from a shipped
bug:

* entry in `LAZY_TAB_SCRIPTS` in `static/js/core.js:768`, plus an entry for any
  other tab hosting one of its controls
* anything cross-module goes on `window` **and** into `types/globals.d.ts`
* no inline handlers — `data-action` plus a delegated listener bound to an id
  that actually exists in `templates/dashboard.html`
* escaping convention `escapeHtml(jsStr(x))`
* i18n keys for every string, both languages

## 13. Testing

Pure functions, no I/O — the property that makes `analyze_config` testable.
Table-driven: `(config text, flow) -> expected verdict + matched rule`.

| File | Covers |
| :--- | :--- |
| `tests/test_policy_model.py` | cube containment, interval merge, non-contiguous wildcards |
| `tests/test_policy_ios.py` | ACE parsing incl. `established`, `neq`, `remark`, opaque fallback |
| `tests/test_policy_fortios.py` | nested addrgrp, builtin services, disabled policy, unresolved object |
| `tests/test_policy_engine.py` | full chain, implicit deny, `no_static_route`, UNKNOWN propagation |
| `tests/test_policy_examples.py` | example inside the cube, near-miss outside it, hint preference |
| `tests/test_policy_findings.py` | shadowed, unreachable, any-any, route-to-nowhere |

`tests/test_lazy_tab_scripts.py` already covers the new tab's registration in
both directions; it must not be narrowed to accommodate the new module.

Fixture configs live in `tests_data/`, RFC 5737 addresses only.

## 14. Version

New feature, new tab, new subsystem → **MINOR** bump. `core/version.py` and
`pyproject.toml` move together.

## 15. Build order

1. `model.py` + its tests — nothing else is meaningful until cubes are right
2. `ios.py` ACE parser + route table + tests
3. `engine.py` full IOS chain + tests
4. `fortios.py` + `builtins.py` + tests
5. `examples.py` + tests
6. `findings.py` + tests
7. `routers/policy_test.py` + MCP tools
8. `static/js/policy-test.js`, template, i18n, `globals.d.ts`
9. version bump, `graphify update .`, full checklist from `docs/development.md` §6
