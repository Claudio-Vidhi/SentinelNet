# Day-0 provisioning walkthrough

How to take a switch or firewall out of its box and give it a first
configuration through SentinelNet, with the hardware in front of you.

This describes what the code actually does, field by field. The reference for
*what each generated command means* is the vendor's own hardening guide; the
reference for *what SentinelNet will send and when* is
[services/switch_provisioner.py](../services/switch_provisioner.py),
[services/fortigate_provisioner.py](../services/fortigate_provisioner.py) and
[routers/provisioner.py](../routers/provisioner.py).

Related: [remote-sites.md](remote-sites.md) for what a bastion can and cannot
carry, [operations.md](operations.md) for where `audit.log` lives.

---

## 1. Before you start

| Requirement | Why |
|---|---|
| An **admin** account | `POST /api/provisioner/push-ssh` and `/push-serial` (and their `/fgt/` twins) are `require_admin`. Generating, downloading and listing serial ports are `require_operator`. A `viewer` never sees the tab at all — the nav entry is `requires-write`. |
| A decided IP plan | The wizard validates nothing. The first thing that checks your input is the device. |
| Physical access **or** a reachable temporary address | Serial delivery needs the cable plugged into the machine running the SentinelNet server, not into your laptop (§7). SSH delivery needs the device already answering on some address. |
| The site record, if the device sits behind a bastion | Create the jump site first ([remote-sites.md §6](remote-sites.md)) — a day-0 device cannot be resolved to a site by IP. |

Two things this feature does **not** do, and you should plan around them:

- **No rollback, no commit-confirm.** There is no `reload in`, no
  `configure replace`, no scheduled revert anywhere in either provisioner. If
  the push half-lands, you go and look.
- **No inventory write.** A successful push does not add the device to
  `network_hosts.csv`. That is a separate step (§9).

---

## 2. The two tabs both called "Provisioning"

The nav entry opens two sibling sub-tabs. They do different jobs and it is
worth being sure which one you are on:

| Sub-tab | id | What it is |
|---|---|---|
| **Provisioning Apparato** | `#tab-provisioning` | Inventory CRUD: register an *existing* device, assign it to a tenant and a physical site, set transports and credentials. Also where tenant credential identities are managed. |
| **Zero-Touch Provisioning** | `#tab-provisioner` | The day-0 wizard. Generates a full config from scratch and delivers it. |

Everything in §3–§8 is `#tab-provisioner`. §9 goes back to `#tab-provisioning`.

---

## 3. Tenant, site and vendor

**The day-0 wizard has no tenant field.** It generates text from the parameters
you type; it does not read tenant defaults and does not tag the result. Tenant
assignment happens later, when you register the device (§9). Two selectors on
the page do mention a tenant or a site, and neither is what you might assume:

- `#genCfgTenant` belongs to the **AI config generator** panel at the top
  ("Genera configurazione nuovo switch"). That panel calls
  `POST /api/ai/generate-config` and writes a proposal into `#genCfgOutput`
  with a Copy button. It does **not** fill the wizard form below and its output
  is never pushed. It is a separate path from the deterministic wizard and is
  out of scope here.
- `#provSshSite` ("Sede del target") is on the SSH delivery panel and only
  affects whether the push is tunnelled through a bastion. See §6.2.

**Vendor** is `#provVendorChips` — two chips, Cisco switch or FortiGate
firewall. The chips are a skin over the hidden `<select id="provVendor">`,
which stays the source of truth; clicking a chip dispatches a real `change`
event, which swaps `#provCiscoSection` for `#provFgtSection` and reveals the
FortiGate console-login fields. Everything downstream (which endpoint is
called, which payload is collected) keys off `#provVendor`.

---

## 4. Filling the Cisco switch form

Most fields are self-evident. These are not.

### 4.1 Role

`#provRole` is `access` or `distribution`, and it changes the generated config
in ways the form only half shows:

| | `access` | `distribution` |
|---|---|---|
| `#provSvisGroup`, `#provDefRouteGroup` | hidden | shown |
| `ip routing` | not emitted | emitted |
| SVIs from `#provSvis` | **ignored** | emitted |
| `ip route 0.0.0.0 0.0.0.0 <gw>` | not emitted | emitted from `#provDefRouteGw` |
| Gateway `#provMgmtGw` → `ip default-gateway` | emitted | **silently ignored** |

That last row is the trap: on a distribution switch the "Gateway" box does
nothing. Use `#provDefRouteGw` instead.

### 4.2 Management VLAN, IP, mask, gateway

`#provMgmtVlan` (the HTML ships a default of `1`) produces
`interface Vlan<n>` + `ip address` + `no shutdown`. Leave it empty and the
device gets **no management interface at all** — a perfectly valid outcome for
a switch you will manage out-of-band, and a silent one otherwise.

The management VLAN is **not** added to the VLAN database automatically. If it
is not VLAN 1, list it in `#provVlans` as well, and in `#provTrunkVlans` if it
has to cross the uplink.

### 4.3 VLAN list syntax

`#provVlans` takes `id:name` pairs separated by commas:

```
10:DATA, 20:VOICE, 99:MGMT
```

Parsing (`provParseVlans` in
[static/js/provisioning.js](../static/js/provisioning.js)):

- The name is optional — `10, 20` yields `VLAN10`, `VLAN20`.
- An entry whose id is not a number is **dropped without a warning**. A typo
  like `1O:DATA` simply produces one VLAN fewer than you expected.
- The name is inserted verbatim after `name`. Nothing rejects a space, so
  avoid spaces in VLAN names here.

`#provSvis` (distribution only) uses a three-part form,
`vlan:ip:mask`, comma separated:

```
10:192.0.2.1:255.255.255.0, 20:198.51.100.1:255.255.255.0
```

Entries missing the IP or the mask are dropped silently, same as above.

### 4.4 Access and trunk port ranges

`#provAccessPorts` and `#provTrunkPorts` are comma-separated lists of
**interface range expressions**, each passed through verbatim to
`interface range <text>`. Nothing parses or validates the interface names — the
device does.

```
GigabitEthernet1/0/1-24                     one range block
Gi1/0/1-12, Gi1/0/20-24                     two range blocks
```

Every access range gets `switchport mode access`, `switchport nonegotiate`,
`spanning-tree portfast`, `spanning-tree bpduguard enable`, `no shutdown`, plus
whatever the port-security / storm-control / DHCP-snooping checkboxes add.
`#provAccessVlan` is a single VLAN applied to *all* access ranges — the form
cannot give different ranges different VLANs.

> **`no shutdown` is unconditional.** Every port in every range you name comes
> up when the config lands. On a switch already cabled into a live network,
> that is the moment loops and rogue DHCP appear. This is exactly what the
> BPDU Guard and DHCP Snooping checkboxes are for.

### 4.5 The trunk VLAN field does double duty

`#provTrunkVlans` feeds **two** different things:

- `switchport trunk allowed vlan <value>` on the trunk ranges and on the
  Port-channel, and
- `ip dhcp snooping vlan <value>` when DHCP Snooping is ticked.

They are the same string. If your snooping VLAN set should differ from your
trunk-allowed set, the form cannot express it — generate, then edit the text
before pushing, or fix it on the device afterwards.

### 4.6 Uplink Port-Channel

`#provUplinkPc` empty means no EtherChannel. Give it a number `N` and:

- every interface in every trunk range gets `channel-group N mode active`
  (LACP active), and
- a logical `interface Port-channelN` is created afterwards, repeating the same
  trunk mode, allowed VLAN list, `switchport nonegotiate` and — if snooping is
  on — `ip dhcp snooping trust`.

The upstream side has to be configured to match. Nothing here checks that.

### 4.7 SNMPv3

The whole SNMP block is emitted **only if `#provSnmpUser` is non-empty**. When
it is, the generated user is `v3 priv`, `auth sha`, `priv aes 128`, in a group
named `SNMP-GROUP`.

> **Leaving the auth/priv boxes empty does not disable them.** An empty
> `#provSnmpAuth` / `#provSnmpPriv` falls back to the literals `authpass123` /
> `privpass123` inside `build_config` — hard-coded, public, and pushed to the
> device as-is. Fill both, or clear the user field.

The same substitution exists for the local admin: `#provAdminUser` filled with
`#provAdminPass` empty produces `username <user> privilege 15 secret changeme`.
The FortiGate form has the identical trap (§5).

### 4.8 AAA

`#provAaaProtocol` is `none` / `radius` / `tacacs`; picking either non-`none`
value reveals `#provAaaServerGroup`, `#provAaaKeyGroup` and the hint.

- The form has room for **one** server, sent only if the IP box is non-empty.
  (The API schema accepts up to three — see §11.)
- Protocol set but IP blank → the payload carries no server, and
  `build_config` silently falls back to the local-only branch:
  `aaa authentication login default local`. You get a config that looks fine
  and has no AAA in it.
- With a server, the local user stays as fallback:
  `aaa authentication login default group SENTINEL-AAA local`. That is the
  behaviour the hint describes, and it is what keeps you out of a lockout when
  the RADIUS box is unreachable.

### 4.9 Checkboxes, and what is hardcoded

The checkbox row maps 1:1 onto flags in `build_config`. `SSH-only` unticked
means `transport input ssh telnet` instead of `transport input ssh`, and skips
the `crypto key generate rsa` / `ip ssh version 2` block. `Errdisable
auto-recovery` derives its causes from which of BPDU Guard, Port-security and
Storm-control are on — with all three off, no recovery lines are emitted at all.

Four values have **no UI control** and are fixed by
[static/js/provisioning.js](../static/js/provisioning.js): VTP mode
`transparent`, STP mode `rapid-pvst`, `enable_routing` true (only consulted for
`distribution`), and `save_after` true (§6.1).

---

## 5. Filling the FortiGate form

### 5.1 MGMT vs WAN vs LAN

Three interface roles, three different meanings. Each block is emitted only
when its own preconditions are met, and skipped in silence otherwise:

| Block | Emitted when | What it produces |
|---|---|---|
| MGMT | `#fgtMgmtIf` **and** `#fgtMgmtIp` are both filled | `set mode static`, the IP, `set allowaccess ping https ssh`, `set alias "MGMT"` |
| WAN | `#fgtWanIf` filled | `set mode dhcp` (default) or `set mode static` + IP/mask; alias `WAN`, `set role wan` |
| WAN default route | mode is **static** *and* `#fgtWanGw` filled | `config router static` entry 1 via the WAN interface |
| LAN | `#fgtLanIf` **and** `#fgtLanIp` both filled | static IP, `set allowaccess ping`, `set role lan`, `set device-identification enable` |

Consequences worth internalising:

- In **DHCP** WAN mode, no static route is generated. The box relies on the
  DHCP-supplied default gateway. Filling `#fgtWanGw` while mode is DHCP does
  nothing.
- `#fgtNoWanAdmin` (ticked by default) sets WAN `allowaccess` to `ping` only.
  Untick it and you get `ping https ssh` on the internet-facing interface.
  Think before you do.
- MGMT `allowaccess` is fixed at `ping https ssh` — the schema field exists but
  the form does not expose it (§11).

### 5.2 DHCP server and the LAN→WAN policy

`#fgtDhcpServer` needs **four** other things to be true before anything is
generated: the tick, `#fgtLanIf`, `#fgtLanIp`, `#fgtDhcpStart` **and**
`#fgtDhcpEnd`. Miss one and the whole block vanishes with no warning.

`#fgtLanToWan` (ticked by default) needs both LAN and WAN interfaces named. The
policy it writes is deliberately blunt — `all` → `all`, service `ALL`, action
accept, NAT enable, `logtraffic all`. It is a day-0 "the site has internet"
policy, not a rule set. Tighten it before the site goes live.

### 5.3 Admin, hardening, AAA

`#fgtAdminUser` creates an **additional** `super_admin` alongside the built-in
one. As on the switch, a blank password yields the literal `changeme`.

`#fgtLockout` → `admin-lockout-threshold 3` / `admin-lockout-duration 120`.
`#fgtStrongCrypto` → `set strong-crypto enable`. `admintimeout` is fixed at 10
minutes with no UI control.

AAA takes a single server. RADIUS writes `config user radius` with `set secret`;
TACACS+ writes `config user tacacs+` with `set key`. Either way a wildcard
remote admin (`remote-sentinel-radius` / `remote-sentinel-tacacs`) is created
with `super_admin` and bound to the `SENTINEL-AAA` user group.

### 5.4 SNMPv3

Same rule as the switch: emitted only when `#fgtSnmpUser` is non-empty, and
blank auth/priv passwords silently become `authpass123` / `privpass123`.
Security level `auth-priv`, `auth-proto sha`, `priv-proto aes`.

---

## 6. Generate and review first

Set `#provDeliveryMode` to **Solo visualizzazione** and click **Genera Config**.
The text lands in `#provOutput`. **Scarica .txt** downloads the same text as
`<hostname>-day0.txt`.

Read it before you push. In particular check the port ranges, the trunk-allowed
list and the management interface, since none of them were validated on the way
in.

> **The generated text is not deployable as-is.** Every secret is replaced by a
> `{{VAULT:<path>}}` placeholder — `{{VAULT:enable_secret}}`,
> `{{VAULT:snmpv3.auth_pass}}`, `{{VAULT:ha.password}}`, and so on. This is
> deliberate and pinned by
> [tests/test_provisioning_secrets.py](../tests/test_provisioning_secrets.py):
> a config you can paste into a ticket must not carry cleartext credentials.
> The push path (§6.1, §7) uses the real values; only the *text* is masked.

A fully materialised file is still possible, but only by calling the endpoint
directly with `?materialized=true` — the UI never sets it — and doing so writes
an `ATTENZIONE: config day-0 ... MATERIALIZZATA` line into `audit.log` naming
you and the target hostname. Treat the resulting file as a credential.

Empty inputs interact badly with masking: a secret you left blank is not masked
(there is nothing to mask), so the `changeme` / `authpass123` fallbacks from
§4.7 appear in the generated text in the clear. If you see one, you forgot a
field.

### 6.1 Push via SSH

Switch `#provDeliveryMode` to **Push via SSH** to reveal `#provSshFields`:

| Field | Notes |
|---|---|
| `#provSshHost`, `#provSshPort` | The address the device answers on **now**, not the one you are about to give it. |
| `#provSshUser`, `#provSshPass` | Credentials the device has now. |
| `#provSshSecret` | Cisco only — the field is not sent for FortiGate. **Left empty, the login password is used as the enable secret.** |
| `#provSshSite` | See §6.2. Default "Automatica (da inventario)". |

Then **Applica via SSH**. What happens on the server:

- Comment lines are stripped before sending — `!` for Cisco, `#` for FortiGate.
  The FortiGate `execute api-user generate-key ...` reminder is a comment, so
  it never reaches the device; that step stays manual.
- **Cisco:** netmiko `cisco_ios` → `enable()` → `send_config_set(...)` →
  `save_config()`. The save is unconditional (`save_after` is hardcoded true in
  the JS). If the save itself fails, the message
  `[Salvataggio configurazione non riuscito: ...]` is appended to the output
  **but the status stays `success`** — read the output, not just the header.
- **FortiGate:** REST first, SSH second. If a FortiGate API token is stored for
  that exact IP (`fortigate_tokens.json`), the config is uploaded as a
  config-script over REST. Otherwise, or if REST fails, netmiko `fortinet` is
  used with `exit_config_mode=False, cmd_verify=False`. The result line in
  `#provOutput` shows ` via api` or ` via ssh`, and `(REST API fallita: ...)`
  when it fell back. FortiOS persists on each `end`, so there is no separate
  save.

> **`status: success` means "the transport did not raise".** Nothing scans the
> device output for `% Invalid input detected`, `command parse error` or any
> other rejection. A config where half the lines bounced still reports success.
> The rejections are in the output text; read them.

### 6.2 Target site: when you need it

`core.net_ssh.ConnectHandler` decides whether to tunnel through a bastion in
this order ([core/net_ssh.py](../core/net_ssh.py), pinned by
`ProvisioningNamesTheSiteExplicitly` in
[tests/test_jump_site.py](../tests/test_jump_site.py)):

1. Look the target IP up in the inventory. If it belongs to a site in `jump`
   mode, tunnel through that site's bastion.
2. Only if the inventory lookup finds **nothing**, use the site you named in
   `#provSshSite`.
3. Tunnel only if that named site is in `jump` mode. Naming a `central` or
   `agent` site changes nothing.

A day-0 device has no inventory row by definition, so step 1 finds nothing and
the connection is dialled **directly from central** — which, for a device
inside a customer network reachable only through a bastion, is a connect
timeout. **Name the site.** The dropdown is filled from `/api/sites` the first
time you switch the delivery mode to SSH.

Note that this is the *jump* mechanism only. An **agent**-mode site does not
relay provisioning pushes: the push is dialled directly from central regardless
of what you select. For an agent site the device must be reachable from central
by IP.

---

## 7. Push via console / serial

This is the real day-0 path: a device straight out of the box has no IP.

Switch `#provDeliveryMode` to **Push via Console/Seriale** to reveal
`#provSerialFields`: `#provComPort`, `#provBaudrate` (default 9600), and — for
FortiGate only — `#fgtConsoleUser` (default `admin`) and `#fgtConsolePass`.

> **The serial port is enumerated on the SentinelNet server, not on your
> browser's machine.** `#btnProvRefreshPorts` calls
> `GET /api/provisioner/serial-ports`, which runs `pyserial`'s port scan in the
> server process. If SentinelNet runs on a different host from the one with the
> USB-serial adapter plugged in, this mode cannot work at all — no amount of
> typing a COM name will help. Run the server on the laptop that holds the
> cable, or use SSH delivery.

The refresh button pops an alert listing every port found *and overwrites
whatever you typed in `#provComPort` with the first one*. Check the field after
clicking it.

What gets sent, with fixed delays and **no prompt matching whatsoever**:

- **Cisco:** blank line → `enable` → `configure terminal` → every config line →
  `end` → `write memory`. There is no login step. The code assumes the console
  is sitting at an unauthenticated or already-privileged prompt, which is true
  for a factory-fresh switch and false for one you have already provisioned
  once (see §8.4).
- **FortiGate:** blank line → username → password → every config line. Nothing
  handles FortiOS's forced first-password change.

Delays are fixed (0.3–1.0 s per line) and the "output" is whatever happened to
be in the receive buffer when each delay expired. It is a rough echo, not a
transcript, and it can miss the device's replies entirely.

---

## 8. Verify

1. **Read `#provOutput` in full.** Not the `[success]` header — the body. Look
   for `% Invalid input`, `command parse error`, `Command fail`.
2. **Reconnect independently** — console, or SSH to the new management address —
   and confirm the running-config. Nothing in SentinelNet re-reads the device
   after a push.
3. **Cisco: confirm it was saved.** A save failure is reported inside a
   `success` response (§6.1). `show startup-config` is the only real answer.
4. **Check `audit.log`** (see [operations.md §1](operations.md)). One line is
   written per download, per materialised generation and per push, naming the
   user, the target host and the resulting status.

---

## 9. Register the device

The push does not touch the inventory. Go to the sibling sub-tab,
**Provisioning Apparato** (`#tab-provisioning`), and add the device:

1. **Tenant** `#devGroupSelect` (`#btnInlineNewTenant` creates one inline).
2. **Physical site** `#devSiteSelect` — for a device behind a bastion, the same
   jump site you named in `#provSshSite`. From now on the site is resolved from
   the inventory and you never name it again.
3. **IP** `#devIp` — the management address the day-0 config just set.
4. **Vendor engine** `#devVendor`.
5. **Transports** `#devTransports` — SSH:22 by default.
6. **Credentials** `#devProfile`: the standard network profile, a tenant
   identity, or dedicated credentials. Whatever you chose, it must match what
   the day-0 config actually configured on the device.

---

## 10. Troubleshooting

### 10.1 The push cuts the path it is riding on

The single most common way to brick a remote day-0 push. The generated config
touches, among other things, `interface Vlan<mgmt>` and its IP, `line vty`,
`transport input`, `aaa new-model` and `login block-for`. Push over SSH *to the
address the config is about to change*, or reshape vty/AAA under your own
session, and netmiko's connection dies mid-`send_config_set`.

What the code does then: the exception is caught and you get
`{"status": "error", "message": "<netmiko error>"}`. That is all.

- Nothing is rolled back. There is no `reload in`, no `configure replace`, no
  commit-confirm anywhere in either provisioner.
- The response carries **no partial output** — you cannot tell from it how far
  the push got.
- On Cisco, `save_config()` is the last step and never runs, so the device's
  *startup*-config is still the old one. Whether power-cycling it recovers the
  box is device behaviour, not something SentinelNet arranges or verifies.
- On FortiOS there is no such grace: FortiOS persists at each `end`, so an
  interrupted FortiGate push is already saved up to the last completed block.

**Avoid it rather than recover from it:** deliver day-0 over console/serial, or
SSH in on an address the config does not touch and move management afterwards.
If you are pushing through a bastion, the same reasoning applies one hop out —
a change to a route or policy the bastion's path depends on kills the tunnel
too.

### 10.2 Device behind a bastion: connect timeout

Symptom: `status: error` with a connection timeout or "no route", on a device
you know the bastion can reach.

Cause: `#provSshSite` left on "Automatica (da inventario)". A day-0 device is
not in the inventory, so there is nothing to resolve and the push is dialled
directly from central (§6.2).

Fix: pick the jump site explicitly. Check that the site really is in `jump`
mode — a `central` or `agent` site in that dropdown is accepted and ignored.

Two bastion-specific errors surface through the same `message` field, and both
mean the *bastion* refused you, not the device:

- **`Il bastione ... ha rifiutato l'utente ...: credenziali del bastione, non
  del dispositivo.`** Fix the site's jump identity. Rotating the device
  credential will not help. Note that a site's cached SSH transport is
  invalidated when you edit the bastion address, port or identity, so the next
  attempt re-authenticates.
- **`Il bastione ... presenta una chiave host diversa da quella registrata.`**
  The pinned host key changed. Either the bastion was rebuilt or someone is on
  the path. Remove the stale line from `ssh_known_hosts` in the data directory
  *only if you know why it changed*.

One more bastion wrinkle, FortiGate only: FortiGate REST does **not** work
through a jump site ([remote-sites.md §6.3](remote-sites.md)). If a token
happens to be stored for that IP, the REST attempt is made first, fails, and
you get `(REST API fallita: ...)` prefixed to the result before the SSH
fallback runs. That line is noise; the real outcome is what follows it.

### 10.3 Wrong or missing enable secret (Cisco)

Two fields are labelled "Enable secret" and they are not the same thing:

| Field | Meaning |
|---|---|
| `#provEnableSecret` (Apparato & parametri) | The enable secret the device **will have** after the push. Goes into the generated `enable secret` line. |
| `#provSshSecret` (SSH delivery panel) | The enable secret used to **log in right now**. |

Leave `#provSshSecret` empty and the code falls back to the SSH login password
(`secret or password`). If neither is right, `conn.enable()` raises before any
configuration is sent: `status: error`, nothing applied, the device untouched.
That is the benign failure.

On a second push to the same switch, the credential you need in
`#provSshSecret` is the one the *first* push installed.

FortiGate has no enable concept — the field is not sent for that vendor, and
`#provSshSecret` being filled is simply ignored.

### 10.4 The COM port is not available

`#btnProvRefreshPorts` returning "Nessuna porta seriale rilevata sul server"
covers several distinct causes, and the code cannot tell them apart:
`list_serial_ports` swallows every exception and returns an empty list. So an
empty result means **any** of:

- the adapter is plugged into a different machine than the server (§7),
- `pyserial` is not importable in the server's environment,
- the USB-serial driver is missing,
- there genuinely is no port.

If you type the port name manually and the open fails, you get a proper
`status: error` with the operating system's message — access denied (something
else holds the port: a terminal emulator, a previous session), or no such file.
Close the other terminal program first; the port is exclusive.

### 10.5 A push that fails partway

What you can and cannot learn from the response:

| Situation | What you get |
|---|---|
| SSH session dies mid-push | `status: error` + the exception text. **No partial output.** How far it got is unknowable from here — reconnect and read the running-config. |
| SSH survives, device rejects some lines | `status: success` + the rejections inside the output text. Nothing scans for them. |
| Cisco save fails after a good push | `status: success` + `[Salvataggio configurazione non riuscito: ...]` appended. |
| Serial, port opened | `status: success`, essentially always. There is no prompt matching and no verification of any kind. |
| Serial, port could not be opened | `status: error` + the OS message. |

There is no retry, no resume and no "apply only what is missing". Re-running
the push re-sends every line from the top. Whether that is harmless depends on
the device and the specific commands (§11), so verify the current state before
you re-run rather than assuming.

A half-applied device leaves no record anywhere except `audit.log` — nothing is
written to the inventory by a push.

### 10.6 Nothing happens when I click Generate

`#btnProvGenerate` and `#btnProvDownload` act only on a `res.ok` response. Any
other status — 403 for an insufficient role, 422 for a payload the schema
rejects — leaves `#provOutput` exactly as it was, with no message. A 401 is
handled globally and logs you out.

The push buttons are slightly worse: they parse the body whatever the status,
so a 403 renders as a bare `[undefined]`. If you see that, you are almost
certainly an `operator` rather than an `admin` — pushes are admin-only.

Open the browser's network tab to see the real status.

### 10.7 Interactive prompts

Neither delivery path answers a question from the device. Serial sends bytes on
a fixed timer with no prompt matching; SSH uses netmiko's defaults with no
custom expect strings and no `confirm` handling. Any generated command that
asks something (`crypto key generate rsa` where keys already exist, FortiOS's
forced password change on first console login, and so on) is unhandled: the
next config line goes into the prompt as the answer.

What the device does in response was **not verified** here — see §11.

---

## 11. Known limits and unverified behaviour

Verified from the code, and worth knowing:

- **The wizard performs no client-side validation.** No required-field check,
  no IP or interface-name syntax check, no cross-field consistency check.
  `hostname` falls back to `Switch` / `FortiGate` if left blank. The first
  thing that ever validates your input is the device itself.
- **Fields in the API schema with no form control.** FortiGate:
  `api_user`, `central_mgmt`, `csf_group`, `netflow_collector`, `ha`,
  `admin_timeout`, `mgmt_allowaccess`, `rest_api_logging`. Switch:
  `aaa_servers` beyond the first (the schema allows three), `vtp_mode`,
  `stp_mode`, `snmpv3.group`, `aaa_servers[].auth_port` / `acct_port`. These
  are reachable only by calling `POST /api/provisioner/…` directly with your
  own JSON body; the UI can neither set nor display them.
- **`rest_api_logging` defaults to true**, so every FortiGate config generated
  from the form carries `config log setting` with `rest-api-set`/`rest-api-get`
  enabled, with no way to turn it off from the UI.

Not verified, and deliberately not documented as fact:

- **What real hardware does with an interactive prompt** (§10.7). The absence of
  prompt handling in SentinelNet is verified; the device's reaction to it was
  not tested and is not described here.
- **Whether re-running a push is idempotent.** Re-sending the full line set is
  what the code does; whether that is safe for a given command on a given
  platform — `crypto key generate rsa`, `channel-group`, an existing
  `config system admin` entry — was not tested.
- **The AI config generator panel** (`#btnGenCfg`, `/api/ai/generate-config`,
  [static/js/ai.js](../static/js/ai.js)). Verified only that it writes text
  into `#genCfgOutput` with a Copy button and does not feed the wizard form or
  any push path. Its output quality and prompt behaviour are outside the scope
  of this document.
