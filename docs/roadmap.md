# Roadmap

What is deliberately not built yet, and why in this order. Nothing here is a
commitment; it is the reasoning that should survive the next six months so the
same debate doesn't get re-run from scratch.

Ordering criterion throughout: **how much new data does it require?** Items that
stand on data already collected come first.

---

## 1. Noise and workflow

Ideas taken from Nagios/Naemon, reordered after checking them against the code.

None of these items make the network more visible. They exist so the engineer
trusts what they read, not so they discover something new. That is a different
goal and worth keeping distinct.

| # | Item | Status | Note |
|---|---|---|---|
| 1 | Flapping detection | **done** | `IFACE_FLAPPING_001` |
| 2 | Windowed suppression (scheduled downtime) | **done** | [suppression.py](../observability/suppression.py), applied in the correlator |
| 3 | Confirm before concluding | to do | The debt that explodes once notifications exist |
| 4 | `device.unreachable` | to do | Silence must become a fact |
| 5 | Full acknowledgement | to do | Three columns, not a feature |
| 6 | Notification engine → escalation | undecided | Out of the original plan's scope |

### 1.1 Why this order

**Flapping first.** The only item requiring no new data, and the noise already
existed: an `IFACE_DOWN_001` on every drop, an `IFACE_RECOVERED_001` retracting
it on every recovery, a conclusion rewritten every cycle. The code already knew
— it's written in the remedy text of `IFACE_RECOVERED_001` — and did nothing
about it.

**Downtime and interface expectations are one model.** One says "this port is
down by design, forever", the other "this device is down by design, from Tuesday
at 22:00". Same question (*was the operator expecting this?*), same
architectural answer: don't suppress the fact, change its interpretation.
Implementing them separately means two places to look when an alarm doesn't
fire. It has to be **one** suppression with an optional window, where "forever"
is the case with no expiry.

**Confirm before concluding — where we disagree with Nagios.** Dismissing
HARD/SOFT on the grounds that "evidence → incident with confidence and
retraction is richer" conflates two problems. HARD/SOFT exists to *avoid
concluding on the first observation*; retraction acts **after** concluding.

While only the UI reads conclusions, that's fine. With a notification engine, "I
concluded, then retracted" means someone was already woken at three in the
morning, and you cannot unsend an email.

That the gap is real shows in the code: `BASELINE_NORMAL_RETRACT_001` exists to
dismantle transient spikes after the fact — a confirmation performed backwards,
paying the price of having concluded in the meantime.

This does not need Nagios's state machine. It needs a rule to declare **how many
observations it requires before producing evidence**: one more parameter in the
catalog. See [ADR-0003](adr/0003-evidence-and-derived-incident.md).

**`device.unreachable` instead of a dependency tree.** Nagios needs UNREACHABLE
because it does active checks: it pings everything and must distinguish "host
failed" from "router in between failed". SentinelNet is passive.

The SNMP poller introduced the first active check, and today a device that stops
answering produces nothing: `_poll_device` returns an empty list and the loop
moves on. **Silence, not a fact.** That's the real gap, and it is far smaller
than a dependency tree. Topological propagation comes later and needs the flow
path over CDP.

**Acknowledgement is already 80% there.** `incidents.status` has
`new → ack → resolved` with constrained transitions and optimistic concurrency.
Missing: `acknowledged_by`, a timestamp and a note. Today the "who" ends up only
in the audit log, not on the incident.

### 1.2 Rejected, and why

| Item | Reason |
|---|---|
| Continuous active checks | SentinelNet observes. The one exception is the poller, which collects state rather than verifying reachability |
| OK/WARNING/CRITICAL states | Evidence with causal roles and confidence says more |
| **Plugin architecture** | The equivalent already exists **twice**: a new source is an adapter in `normalize.py`, new logic is an entry in `RULES`. A third mechanism would only give three places to look |

"Passive checks" isn't an item: flows, syslog, API and SNMP *are* passive
observations already.

---

## 2. Separating the agent control plane from the device data plane

Remote-site security and remote-device management should be **separate planes**.
They cooperate, but they answer different questions and should not share an
all-or-nothing authority boundary:

| Plane | Principal | Responsibility | Must not grant |
|---|---|---|---|
| Agent / control | The registered site agent | Prove agent identity, deliver work, report health, inventory and results | Unrestricted access to every device or every possible action |
| Device / data | A device identity and its credential/policy | Connect to, observe and change one device | Authority to impersonate the agent, create jobs, or administer central |

**Sound today:** the agent connects outbound over HTTPS only, central needs no
inbound access to the site, central authenticates the agent with a per-site
token (stored as a SHA-256 hash), and device credentials stay in the agent's
local data directory. That already limits credential exfiltration from a
compromised central server.

**Not yet separated:** an authenticated agent receives *all* pending jobs for
its site and executes them using whichever local device record matches the
requested IP. Agent identity therefore implies full device authority within the
site.

If this gets built, it belongs in an ADR — it changes an authority boundary, not
just an implementation. See [remote-sites.md](remote-sites.md).

---

## 3. Server integrations (Linux / Windows)

**Linux shipped**; Windows is still a proposal. Ordered by value-to-effort ratio.

### Done

1. ~~**Servers as inventory devices.**~~ **Linux: shipped.** `drivers/linux.py`
   plus a `linux` branch in the extra-command chain make a Linux host a normal
   managed device — backup, triage, Config Analyzer, CIS audit, health poller.
   What it collects and which view each command feeds:
   [server-collection.md](server-collection.md).
   **Windows over WinRM (`pywinrm`) is still open** and would follow the same
   shape: a driver, an artefact with the same `--- <section> ---` markers, and
   an analyzer that turns it into the existing envelope.

6. ~~**Config backup for servers.**~~ **Shipped for Linux** as part of item 1 —
   the artefact *is* the backup: a dump of critical `/etc` files plus command
   output, in `backup-config/` like any switch.

### High value, low effort

2. **MAC → server correlation.** Automatically match server MACs against
   `mac_history`, so the map can say "this server is on SW-X Gi1/0/12". No new
   collector — just a join.

3. **Central syslog receiver.** Already shipped for network devices
   ([collectors.md](collectors.md) §5); extending it to Linux (rsyslog) and
   Windows (NXLog or native forwarding) is configuration on the sending side
   plus UI work on this side.

### Medium value

4. **Service health checks.** Ping and TCP port checks (SSH 22, RDP 3389,
   HTTP/S, database ports) against registered servers, with green/red state in
   the dashboard and on the map. Reuses `network_scanner`.

5. **Server vulnerabilities via EUVD.** The EUVD lookup already exists for
   network vendors (`inventory_manager.resolve_euvd_term`); extending it to
   server operating systems needs only the version from SSH/WinRM inventory.

### Larger efforts

7. **Unified remote agent** — the same site agent also collects local server
   data: one deployment per site.
8. **AD/LDAP integration** — SentinelNet login with domain credentials, and the
   AD computer list as an inventory source.
9. **SNMP against servers.** Note the transport is *not* missing: the SNMP
   poller ([collectors.md](collectors.md) §6) already polls any inventory device
   with a community set, vendor-agnostically, so a server running net-snmp is
   collected today with no new code — sysDescr/sysName/sysLocation/uptime plus
   full IF-MIB per interface. What is genuinely absent is `sysContact`
   (one scalar OID) and the CPU/RAM/storage/sensor MIBs
   (HOST-RESOURCES, UCD-SNMP, ENTITY-SENSOR). For Linux the first three are
   already covered over SSH by the health poller, so this only pays off for
   Windows and for appliances where SSH is not an option.

**Suggested entry point:** item 2. It reuses almost all existing code and makes
the map immediately more useful. Then 3 and 4.

---

## 4. Known limitations tracked elsewhere

These are accepted trade-offs rather than roadmap items, but they are the things
most likely to be mistaken for bugs:

- Observability does not scale horizontally
  ([ADR-0004](adr/0004-single-process-sqlite-writer.md)).
- Tenant attribution breaks for exporters behind NAT
  ([ADR-0005](adr/0005-strict-tenant-attribution.md)).
- The flow path is logical, not packet-by-packet
  ([architecture.md](architecture.md) §5).
- Flow SIEM deep-scan cost
  ([live-flows-and-siem.md](live-flows-and-siem.md) §9).
- Open security findings — tracked in `data/security/`, outside the public tree
  ([CONTRIBUTING.md](../CONTRIBUTING.md) §6).
