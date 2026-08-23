# Network Security Operational Triage & Troubleshooting Q&A Guide — v3

> **Status**: supersedes `netsec_troubleshooting_qa.md` (original, many wrong routes/IDs) and
> `netsec_troubleshooting_qa_corrected.md` (correct on 2026-08-08, superseded).
> Verified on **2026-08-22** against `HEAD = e8f006b`, checking `routers/*.py`, `redundancy/router.py`,
> `ai/mcp_server.py`, `routers/mcp.py`, `templates/dashboard.html` and `static/js/*.js`.
> Two items below were read from the **uncommitted working tree**, ahead of that commit, and say so
> where they appear: the bastion SSH host-key pinning (`core/net_ssh.py`) and the numbered-ACL
> declaration string (`routers/policy_test.py`).
> Line numbers are those of that commit and drift with any edit — treat them as hints, not contracts.
> `templates/dashboard.html` is being annotated with `data-i18n` attributes as this is written, so it
> is cited **by element id only**, never by line number.

## What changed since the 2026-08-11 verification

| Area | Change |
| :--- | :--- |
| **Policy & Routing Validation (new §10)** | A whole new tab, `#tab-policy-test` (nav `#navPolicyTest`, "Validazione Policy & Routing", preview badge, under **Valuta**), served by `routers/policy_test.py` over `services/policy_test/`. Offline evaluation of a packet against the freshest stored backup: `POST /api/policy-test/{ip}/trace`, `GET /examples`, `GET /findings` and `POST /prove`. Two new MCP tools, `policy_trace` and `policy_findings` — the surface is **45 tools**, not 43. |
| **Findings that prove themselves** | Every finding about packet coverage (`shadowed`, `unreachable`) now carries a **witness packet** (`witness` + `expected_rule_id`). `POST /api/policy-test/{ip}/prove` re-traces that packet through the same evaluator the tracer uses and answers `proven: true/false`; a disagreement between detector and evaluator is reported, not hidden. |
| **Findings surfaced across the app** | The same detector feeds four surfaces, not only its own tab: Config Analyzer pill **Validazione** (`data-view="validation"`), FortiGate pill **Policy** (a rule both shadowed *and* never hit is marked as a dead rule), the NetSec Audit report (`policy_defects`, deliberately **outside** the compliance score), and MCP `policy_findings`. |
| **Jump / bastion sites (new §7.2)** | Site `mode: "jump"` tunnels netmiko through an SSH bastion (`core/net_ssh.py`). The bastion identity is editable after site creation, editing host/port/identity invalidates the cached transport, and `POST /api/sites/test-bastion` probes the credential as configured *now*. |
| **HA / Redundancy** | `#tab-redundancy` gained a tenant filter `#haTenantFilter` that also re-scopes the KPI tiles, and Cisco wireless-controller HA (SSO) joined stack / ha_pair among the detected group types. |
| **Customizable device export (new §11)** | `GET /api/export/devices` gained a column registry (published by `GET /api/export/devices/columns`) plus group/site/vendor/redundancy filters, still clipped by `user_group_scope`. Per-member columns explode one row per physical unit. |
| **Device serial** | `get_serial()` on the drivers, persisted by `services/inventory_manager.py` and exportable as the `serial` column (§11). |
| **NetSec Audit** | The **Checklist Audit Firewall tab was merged into NetSec Audit** as a sub-tab: `#tab-audit-checklist` and `#navAuditChecklist` no longer exist. The tab is **no longer admin-only**. Saved-run history, a status filter and PDF/DOCX/HTML export from a report modal all landed. |
| **No inline handlers** | `templates/dashboard.html` now contains **zero** `onclick=`. Every `onclick="…"` quoted by the 2026-08-11 version is gone; controls are cited by id or by `data-action` below. |
| **Line numbers** | Most `routers/*.py` line numbers moved; FortiGate moved furthest (policy-lookup 264 → 303, diagnose-client 327 → 366) and `routers/observability.py` moved *up* (health 671 → 635). |
| **Config Drift (new §12, landed 2026-08-23, after this doc's 2026-08-22 verification pass)** | A whole new tab, `#tab-config-drift` (nav `#navConfigDrift`, "Config Drift", no preview badge, under **Valuta**), served by `routers/config_drift.py` over `services/config_drift/`. Per-tenant version history with no pruning, a rule-based (not scored) baseline, and an optional git mirror for archive redundancy only. Seven routes, all under `/api/drift`; no new MCP tool. This section was written and spot-checked against source at commit `4b40ea0f`, not against the same full-doc verification pass as the rest — treat citations here with the same care, not as re-verified history. |
| **Classification export (new §11 Q11.2, landed 2026-08-23, after this doc's 2026-08-22 verification pass)** | `Dispositivi Scoperti & Classificazione` gained a server-side CSV export mirroring the fleet inventory export: `GET /api/export/classification/columns` and `GET /api/export/classification`, replacing the old browser-side CSV builder in `static/js/topology.js`. Two columns the inventory export does not have: **serial** and **neighbour device/port**. Written and spot-checked against source at commit `7f14a04`, not against the same full-doc pass as the rest. |

## Still true from the corrected version (do not regress)

- MCP tools live in `ai/mcp_server.py` (`TOOLS` dict), **not** `routers/mcp.py` — that router only serves
  `/api/mcp/settings` and `/api/mcp/tool-config`.
- `get_top_talkers`, `get_anomalies`, `linux_health` are **disabled by default**
  (`routers/mcp.py:15`, `_MCP_DEFAULT_DISABLED`) until an admin enables them. No other tool is.
- The FortiGate tab is built from panes `#fgtPane-*` (switched by the `#fgtSub-*` button bar, delegated
  from `#fgtSubtabBar`) and view pills `#fgtPill-*` rendering into `#fgtView-*`. There is no
  `#subtab-*` family anywhere. Still 7 panes and 25 pills.
  *(Both earlier documents, and the first draft of this one, called `#fgtSub-*` the panes — those are
  the bar buttons; the containers are `#fgtPane-*`.)*
- The Cisco WLC tab loads through the single consolidated `GET /api/wlc/{ip}/overview` (one SSH
  session: AP + client + WLAN + rogue), with tenant-first selection `#wlcTenantSelect` →
  `#wlcTargetSelect`. The per-object routes still exist for API/MCP consumers; the UI does not call
  them one by one.
- The subnet scan is **discovery-only**; credential verification is the separate opt-in
  `POST /api/scan-verify` using stored identities.
- Traffico is one tab with four views (`#trafPill-*` → `#trafPane-*`); `#tab-flow-siem` does not exist.
  Localizzazione Endpoint is one tab with four panes (`#locPill-*` → `#locPane-*`); `#tab-diagnosi`
  does not exist.
- Routes that exist **API-only, with no UI button**: `POST /api/flow-siem/shun-ip` is now the *only*
  one (deferred by the owner, see `docs/Improvements`). `POST /api/mac/port-control`,
  `DELETE /api/fortigate/{ip}/sessions` and `POST /api/observability/prune-logs` all got their buttons
  during August 2026 and are **not** API-only — do not re-add them to this list.
- These routes named by the original document **still do not exist**:
  `/api/fortigate/{ip}/managed-aps`, `/api/mac/mac-to-ip`, `/api/mac/client-map`,
  `/api/endpoint-inventory`, `/api/flow-siem/top-talkers`, `/api/flow-siem/anomalies`,
  `/api/analyzer/config`, `/api/triage/status`, `/api/ai/diagnose`,
  `/api/observability/linux-health`, `/api/observability/status`, `/api/topology/map`,
  `/api/provisioner/generate-fortigate-config`.
  *(`POST /api/topology/reset` does exist — it is not the same route as `/api/topology/map`.)*
- Removed in August 2026 and **no longer existing**: `POST /api/provisioner/fgt/push-ssh` and
  `POST /api/provisioner/fgt/push-serial`. SentinelNet no longer delivers a FortiGate day-0 config
  — `/api/provisioner/fgt/generate` and `/fgt/download` remain and the operator applies the text
  itself. The Cisco `POST /api/provisioner/push-ssh` and `/push-serial` are untouched and still work.

---

## Overview & System Context

SentinelNet provides network security observability, triage, client diagnosis, offline policy
validation and configuration auditing across multi-vendor infrastructure: Fortinet FortiGate
firewalls, Cisco Wireless LAN Controllers (AireOS and Catalyst 9800), campus switches (Cisco, Aruba,
HP) and Linux hosts. Remote sites are reached by direct poll, by a site agent, or through an SSH
bastion (§7.2).

All addresses, hostnames and MACs below are documentation examples (RFC 5737 / RFC 7042), never real
customer values.

---

## 1. Firewall Policy Triage & Traffic Inspection

### Q1.1: Outbound web traffic to `198.51.100.45:443` is dropped by core firewall `192.0.2.1`. How to diagnose policy evaluation and rule match?

- **Answer**:
  1. Run a dry-run policy lookup on the FortiGate with source `192.0.2.105`, destination
     `198.51.100.45`, protocol `TCP`, port `443`.
  2. Read the matched policy fields (policy ID, action, src/dst interface, service, NAT, status).
  3. Query the active session table filtered by source/destination to see whether a session exists,
     and inspect protocol, ports, policy ID and duration.
  4. Query the traffic log for the same pair to read log action and policy ID.
  5. Check the route for `198.51.100.45` (Routing pill) to confirm the egress interface matches the
     policy's interface pair.
  6. Shortcut: the **Diagnosi Client** pill runs steps 1–4 in one call for a client IP/MAC.
  7. If the matched policy is not the one you expected, the rule that shadows it is already named:
     the **Policy** pill marks a rule covered by an earlier one, and §10 traces the same packet
     offline against the backup.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Fortigate Management` (`#navFortigate` → `#tab-fortigate`) under **Inventario**, admin-only.
  - **Structure**: a subtab bar of buttons `#fgtSub-overview` / `-network` / `-firewall` / `-traffic` /
    `-security` / `-wifi` / `-settings` (delegated from `#fgtSubtabBar`) toggles the pane containers
    `#fgtPane-overview` … `#fgtPane-settings`. Each pane holds view pills `#fgtPill-*`
    rendering into `#fgtView-*`, plus a shared `Aggiorna` (`data-action="fgt-refresh"`, delegated on
    `#tab-fortigate`). Target selector `#fgtTargetSelect`. 7 panes, 25 pills.
  - **Policy Lookup**: pane **Firewall** → pill `Verifica Policy` (`#fgtPill-policyLookup`) → form
    `#fgtForm-policyLookup`: `#fgtLookupSrc`, `#fgtLookupDst`, `#fgtLookupProto` (TCP/UDP/ICMP),
    `#fgtLookupPort`, `#fgtLookupIntf` → run button `#btnFgtLookupRun`.
  - **Sessions**: pane **Traffico** → pill `Sessioni` (`#fgtPill-sessions`) → `#fgtSessSrc`,
    `#fgtSessDst`, `#fgtSessPort` → `#btnFgtSessLoad`, with `#btnFgtSessionKill` next to it.
  - **Logs**: pane **Traffico** → pill `Log` (`#fgtPill-logs`) → `#btnFgtLogLoad`, `#fgtLogDevice` (disk/memory),
    `#fgtLogType` (traffic/event/utm), `#fgtLogSubtype` (forward/local/virus/webfilter/ips),
    `#fgtLogSrc`, `#fgtLogDst`, `#fgtLogAction`, `#fgtLogSince`/`#fgtLogUntil`, `#fgtLogCount`.
  - **Client diagnosis**: pane **Traffico** → pill `Diagnosi Client` (`#fgtPill-clientDiagnosis`) →
    run button `#btnFgtDiagRun` → aggregated device-inventory + ARP + DHCP + sessions +
    policy match + recent logs for one client. The same pane also holds `Inventario Dispositivi`
    (`#fgtPill-deviceInventory` — FortiGate-discovered devices, unrelated to the Network Inventory tab).
  - **Dead rules**: pane **Firewall** → pill `Policy` (`#fgtPill-policies`) joins the runtime counters
    to the static findings read from the backup. A rule merely never hit is amber; a rule that is
    shadowed **and** never hit is red and labelled a dead rule. The response carries
    `shadow_analysis: "backup" | "unavailable"` — without a backup the column simply does not appear,
    rather than declaring never-examined rules healthy.
- **Workflow Step-by-Step**:
    1. Open **Fortigate Management** under **Inventario**; pick `192.0.2.1` in `#fgtTargetSelect`.
    2. Pane **Firewall** → pill **Verifica Policy**; fill `192.0.2.105` / `198.51.100.45` / `443`, run.
    3. Pane **Traffico** → pill **Sessioni**; `#fgtSessSrc = 192.0.2.105`, load.
    4. Pill **Log**: `disk` + `traffic` + `forward`, load, inspect denied rows.
    5. Or skip 2–4: pill **Diagnosi Client**, enter the client and the destination.

- **App Features Present**:
  - `POST /api/fortigate/{ip}/policy-lookup` ([routers/fortigate.py:303](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L303))
  - `POST /api/fortigate/{ip}/sessions` ([routers/fortigate.py:311](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L311))
  - `DELETE /api/fortigate/{ip}/sessions` ([routers/fortigate.py:318](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L318)) — button `#btnFgtSessionKill`, refuses an empty filter set
  - `POST /api/fortigate/{ip}/logs` ([routers/fortigate.py:341](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L341))
  - `POST /api/fortigate/{ip}/diagnose-client` ([routers/fortigate.py:366](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L366))
  - `GET /api/fortigate/{ip}/firewall/policies-with-stats` ([routers/fortigate.py:257](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L257)) — hit counts, active sessions, last used, **plus per-policy `findings`** joined from the backup by `_shadow_by_policy_id` (L226)
  - **MCP**: `fortigate_policy_lookup`, `fortigate_sessions`, `fortigate_traffic_logs`,
    `fortigate_policies`, `fortigate_policy_stats`, `fortigate_diagnose_client`, `fortigate_full_config`,
    and — offline, from the backup — `policy_trace` / `policy_findings` (§10)
    ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py))
  - **UI**: `static/js/fortigate-management.js` (views registered in `FGT_DATASETS`)

- **Missing Features / Gaps**:
  - **Live Packet Capture**: no `diagnose sniffer packet` integration; no PCAP from the UI.
  - **UTM Detailed Event Breakdown**: UTM sub-log fields (AppCtrl, AV, SSL-inspection failure reasons)
    are not parsed into dedicated cards.
  - *(Withdrawn 2026-08-11: "Session Kill UI" — the button exists in the Sessioni form and refuses to
    run with all three filters empty.)*
  - *(Not a gap: policy hit-count telemetry — it exists, see `policies-with-stats`.)*

---

### Q1.2: Host `192.0.2.50` needs SSH (`22`) and HTTPS (`443`) toward `198.51.100.20`. How to verify existing objects and generate compliant FortiOS configuration?

- **Answer**:
  1. Open **Config Analyzer** and search the parsed backup for address/service objects matching
     `192.0.2.50` and `198.51.100.20`.
  2. Be aware of the scope limit: **Provisioning generates day-0 bootstrap configs** (management/WAN/LAN
     interfaces, DHCP, DNS, NTP, syslog, SNMPv3, AAA, hardening flags), **not** individual policy blocks
     from a src/dst/service form. A single-policy change stays a manual CLI activity informed by the
     analyzer output.
  3. Review the generated FortiOS CLI (`config system interface`, LAN→WAN `config firewall policy`,
     hardening) and check logging/admin-access lines.
  4. Download the `.txt` and apply it yourself — SentinelNet does not push a FortiGate config.
     (SSH and serial/console push exist for the Cisco switch only.)

- **UI Navigation & Operational Workflow**:
  - **Tabs**: `Config Analyzer` (`navAssess` → `#tab-config`), and — under the single nav item
    "Provisioning" (`navChange`, requires-write) — **two distinct surfaces**: `#tab-provisioning`
    ("Provisioning Apparato" = device onboarding CRUD, tenant/transport/credential fields) and
    **`#tab-provisioner`** ("Apparato da Zero" = day-0 config generation). Everything below lives in
    `#tab-provisioner`, not `#tab-provisioning`.
  - **Config Analyzer**: tenant filter `#configGroupSelect`, search `#caSearch`, pills `#caPills`
    (Home / VLAN / Routing / ACL / Interfacce / **Validazione** / Firewall / Server / Converti, as
    `data-view="home|vlan|routing|acl|iface|validation|firewall|server|convert"`), results `#caResults`.
    The analysis auto-loads from `GET /api/config-analyzer?group=<group>`; there is **no**
    `#configSelectBackup`, **no** `#btnAnalyzeConfig` and **no** upload control in this tab
    (upload lives in NetSec Audit, see §6). The **Validazione** view lists unused/missing ACLs,
    unused/undefined VLANs, route→ACL references and — first in the list, because a rule that states
    an intent and silently does nothing is worse than one that was never applied — the
    `policy_findings` from the §10 engine.
  - **Provisioning (`#tab-provisioner`)**: FortiGate day-0 fields (`#fgtMgmtIf`, `#fgtMgmtIp`,
    `#fgtWanIf`, `#fgtWanMode`, `#fgtLanIf`, DNS/NTP/Syslog/SNMPv3/AAA, hardening checkboxes) or Cisco
    switch fields (`#provHostname`, `#provRole`, VLAN/port fields) → `#btnProvGenerate`,
    `#btnProvDownload`. Delivery mode `#provDeliveryMode` and its SSH / serial panels are for the
    Cisco switch; a FortiGate stops at generate + download. The console-login fields
    `#fgtConsoleUser` / `#fgtConsolePass` no longer exist.

- **App Features Present**:
  - `GET /api/config-analyzer` ([routers/analyzer.py:52](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/analyzer.py#L52)),
    `GET /api/config-analyzer/{ip}` (L57), `POST /api/config-analyzer/convert` (L75, FortiOS ↔ PAN-OS)
  - `POST /api/provisioner/fgt/generate`, `/fgt/download` (generation only — there is no FortiGate
    push route); Cisco `/api/provisioner/generate`, `/download`, `/push-ssh`, `/push-serial`,
    `GET /api/provisioner/serial-ports`
    ([routers/provisioner.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/provisioner.py)).
    The two push routes are admin-gated (`require_admin`); generate/download are `require_operator`.
  - Identity store for push credentials: `GET/POST /api/identities` (L316/L321),
    `PUT/DELETE /api/identities/{id}` (L331/L343), `POST /api/identities/{id}/assign` (L360).
    The same store backs the bastion login of a jump site (§7.2).
  - **MCP**: `generate_fortigate_config`, `generate_switch_config`, `analyze_config`
  - **UI**: `static/js/config-analyzer.js`, `static/js/provisioning.js`

- **Missing Features / Gaps**:
  - **Policy-Object Provisioning Form**: no UI/API generating a single policy block from
    (src, dst, services, interfaces, action).
  - **Transactional Push With Rollback**: the Cisco push (SSH/serial) has no commit verification and
    no auto-rollback on failure/connectivity loss.
  - *(Withdrawn 2026-08-22: "Shadow Policy Detector" — `services/policy_test/findings.py` detects
    shadowed, unreachable, any-any, unresolved-object and route-to-nowhere rules, and §10 traces a
    proposed flow against the backup before anyone writes a new rule. It is still not wired into the
    provisioning form as a pre-flight check: the operator has to go and look.)*

---

## 2. Campus MAC Tracing, ARP Discovery & Host Isolation

### Q2.1: A suspicious MAC `AA:BB:CC:DD:EE:FF` is flagged. How to locate switch port, VLAN and IP?

- **Answer**:
  1. Search the MAC across indexed devices (partial/OUI accepted).
  2. Results are grouped per switch; trunk/uplink sightings are shown alongside edge ports so the
     operator can pick the access port (e.g. `switch-01` / `GigabitEthernet1/0/14`, VLAN 10).
  3. Resolve MAC → IP from gateway ARP tables: `GET /api/arp/search` and `GET /api/arp/client-map`.
  4. For the full L2+L3 report on that host, use the **Diagnosi Client** tab (§9) — it resolves port,
     VLAN, gateway, path and firewall policy in one shot.
  5. Containment: `POST /api/diagnose/port-bounce` (admin, **has a UI button** in Diagnosi) bounces the
     access port; `POST /api/mac/port-control` (admin, **has UI buttons** in the same block) shuts it
     down and leaves it down until someone re-enables it.

- **UI Navigation & Operational Workflow**:
  - **Tab** `Localizzazione Endpoint` (`navInvestigate`), `#tab-endpoint` — one tab, four pills
    `#locPill-mac` (MAC Tracker), `#locPill-clientmap` (Client Map), `#locPill-diagnosi` (Diagnosi
    Client), `#locPill-inventory` (Inventario Endpoint) over panes `#locPane-mac` / `#locPane-clientmap`
    / `#locPane-diagnosi` / `#locPane-inventory`, sharing one header and tenant selector.
  - **MAC Tracker**: `#macSearchMac` (partial/OUI ok), `#macSearchVlan`, `#macSearchIface`,
    `#macSearchSwitch`; search `#btnMacSearch`, reset `#btnMacSearchReset`; results `#macResults`.
    KPI tiles above the pane: `#kpiMacSightings`, `#kpiMacUniqueMacs` (clickable,
    `data-action="focus-mac-results"`), `#kpiMacSwitches`, `#kpiMacRetention` — there is **no**
    `#macStats` chip any more. Collection controls: `#macDeviceMenu` / `#macDeviceList`,
    `#macScanTransport`, `#btnMacScan`, plus per-device command overrides (`#macOvDevice`,
    `#macOvCommand`, `#macOvFmt`, `#btnSaveMacOverride`, `#macOverridesList`).
  - **Client Map**: MAC↔IP bindings from gateway ARP tables cross-referenced with tracker ports.

- **App Features Present**:
  - `GET /api/mac/search` ([routers/mac.py:139](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mac.py#L139)),
    `GET /api/mac/locate` (L158), `GET /api/mac/switch/{ip}` (L190), `GET /api/mac/stats` (L195)
  - `POST /api/mac/scan` (L105) — on-demand MAC-table collection;
    `POST /api/mac/settings` (L206) and the override CRUD (L212/L216/L227)
  - `POST /api/mac/port-control` (L242) — admin; persistent isolation, refused on an uplink or a
    stale position; re-enabling asks for neither
  - MAC→IP / Client Map: `GET /api/arp/search` ([routers/arp.py:53](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/arp.py#L53)),
    `GET /api/arp/client-map` (L62), `GET /api/arp/stats` (L85)
  - **MCP**: `locate_mac`, `search_mac`, `mac_to_ip` (→ `/api/arp/search`), `client_map`
    (→ `/api/arp/client-map`)
  - **UI**: `static/js/client-map.js`

- **Missing Features / Gaps**:
  - **802.1X / RADIUS Telemetry**: no RADIUS auth history (username, EAP method, posture) per MAC from
    Cisco ISE or FreeRADIUS.
  - *(closed 2026-08-12)* **Port Shutdown UI**: the Diagnosi port-action block now has Isola / Riattiva
    porta next to the bounce.

---

### Q2.2: Range `192.0.2.128/25` shows abnormal activity. How to discover hosts and populate the endpoint inventory?

- **Answer**:
  1. Collect ARP tables from the selected L3 gateways/firewalls for the tenant.
  2. Aggregate bindings (IP, MAC, interface, gateway).
  3. Cross-reference against the endpoint inventory (`GET /api/endpoints/list`) and flag uncatalogued
     bindings.
  4. For hosts not in inventory at all, run a **discovery-only subnet scan**
     (`POST /api/scan-subnet`) — since the 2026-08-10 rework the scan **does not attempt any login**.
     If a discovered host must be identified, run the opt-in `POST /api/scan-verify` with a stored
     identity; credentials never travel through the discovery path.
  5. Results are persisted for temporal comparison.

- **UI Navigation & Operational Workflow**:
  - The ARP collection panel lives in **Client Map** (`#locPane-clientmap`), **not** in the MAC Tracker
    pane (`#locPane-mac`).
  - Controls: gateway multi-select `#arpDeviceMenu`, `#btnArpScan`, filters `#arpSearchMac` /
    `#arpSearchIp` with `#btnArpSearch`, KPIs `#kpiArpBindings`, `#kpiArpUniqueMacs`,
    `#kpiArpGateways`.
  - **Inventario Endpoint** (`#locPane-inventory`): mode buttons `#epModeListBtn` / `#epModePortsBtn`,
    switch select `#epPortsSwitch`, filters `#epFilterQ`, `#epFilterStale`,
    exports `endpointsExport('csv'|'json')`, KPIs `#epKpis`, results `#epResults`.

- **App Features Present**:
  - `POST /api/arp/scan` ([routers/arp.py:21](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/arp.py#L21))
  - `GET /api/endpoints/list` ([routers/endpoint_inventory.py:35](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/endpoint_inventory.py#L35)),
    `GET /api/endpoints/ports` (L52) — there is no `/api/endpoint-inventory`
  - `POST /api/scan-subnet` ([routers/scan.py:73](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/scan.py#L73)),
    `POST /api/scan-verify` (L165), `GET /api/scan-subnet/{job_id}` (L205)
  - **MCP**: `arp_scan`
  - **UI**: `static/js/endpoint-inventory.js`, `static/js/devices.js`

- **Missing Features / Gaps**:
  - **Active OS Fingerprinting**: discovery probes ports and ARP only; no Nmap-grade OS fingerprinting
    or banner-based device typing.
  - **DHCP Snooping Cross-Check**: no reading of switch DHCP-snooping bindings to detect ARP spoofing.

---

## 3. Wireless LAN Client Disconnects & Rogue AP Containment

### Q3.1: A user on `00:11:22:33:44:55` keeps dropping off Wi-Fi on WLC `192.0.2.10`. How to troubleshoot?

- **Answer**:
  1. Select the **tenant**, then the controller — the controller list is filtered to the WLCs of that
     tenant (vendor `cisco_wlc` / `cisco_9800`).
  2. The tab loads everything through `GET /api/wlc/{ip}/overview`: AP list, associated clients, WLANs
     and rogue APs in one SSH session.
  3. Read the client row: connected AP, SSID/WLAN, RSSI/SNR, quality verdict, bytes.
  4. Run the per-client diagnostic (`GET /api/wlc/{ip}/diagnose-client/{mac}`) for authentication,
     DHCP, EAPOL and low-RSSI flags.
  5. Check the AP row for client density and the per-band channel/width reported by
     `show ap auto-rf 802.11a` (5 GHz) and `show ap auto-rf 802.11b` (2.4 GHz) on AireOS, to spot
     co-channel or width mismatches. Channel utilization is carried in the cell's tooltip.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Cisco WLC` (`#navWlc` → `#tab-wlc`).
  - **Controls**: tenant select `#wlcTenantSelect`, controller select `#wlcTargetSelect` (disabled
    until a tenant is picked), `Aggiorna`, status panel `#wlcStatusBox`.
  - **Tables**: AP `#wlcApTableBody` (name, IP, ethernet MAC, state, clients, **5 GHz** and
    **2.4 GHz** channel `@` width — one column each, utilization in the `title` — model),
    clients `#wlcClientTableBody` (MAC, IP, AP, WLAN/SSID, RSSI/SNR, **quality**, actions) with
    counter `#wlcClientCount` and live filter `#wlcClientSearch`, WLANs `#wlcWlanTableBody`,
    rogues `#wlcRogueTableBody`.
  - **Diagnostics**: row action → modal `#wlcDiagModal` / `#wlcDiagModalBody`. The same route is
    reachable from the Diagnosi Client report (§9), on demand.

- **App Features Present**:
  - `GET /api/wlc/{ip}/overview` ([routers/wlc.py:39](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/wlc.py#L39)) — **the only route the tab calls for telemetry**
  - `GET /api/wlc/{ip}/status` (L50), `/ap-summary` (L54), `/client-summary` (L58), `/client/{mac}` (L62),
    `/wlan-summary` (L66), `/rogue-aps` (L70), `/interfaces` (L74), `/diagnose-client/{mac}` (L78)
  - **MCP**: `wlc_status`, `wlc_ap_summary`, `wlc_client_summary`, `wlc_client_detail`,
    `wlc_wlan_summary`, `wlc_rogue_aps`, `wlc_diagnose_client`
  - **Service**: `services/wlc_service.py` (`overview()`, table parsers for AireOS and 9800)
  - **UI**: `static/js/wlc.js`

- **Missing Features / Gaps**:
  - **802.11 Roaming Event Timeline**: no history of 802.11r/k/v transitions between APs.
  - **AP RF Heatmap**: tabular RF data only, no floor-plan overlay.
  - **6 GHz auto-RF**: both AireOS radios are parsed now (`802.11a` and `802.11b`,
    one column each in the AP table). 6 GHz is not reachable from this code path:
    AireOS stops at 802.11ax 2.4/5 GHz, so it would need the IOS-XE branch, which
    fetches no auto-RF at all.

---

### Q3.2: A rogue AP broadcasts a spoofed corporate SSID. How to locate it and rate the threat?

- **Answer**:
  1. Read the rogue table from the WLC overview (BSSID, SSID, channel, RSSI, classification).
  2. Cross-check FortiGate-managed FortiAP telemetry (`/wifi/aps`, `/wifi/clients`) for the same signal.
  3. Use the detecting AP with strongest RSSI to approximate the physical area.
  4. Search the rogue BSSID in MAC Tracker: a hit on a switch MAC table means the rogue is **wired**
     into the LAN, which raises severity and changes the containment path to the switch port.

- **UI Navigation & Operational Workflow**:
  - `Cisco WLC` (`#tab-wlc`) rogue table `#wlcRogueTableBody`.
  - `Fortigate Management` pane **WiFi** (`#fgtSub-wifi`) → pills `FortiAP` (`#fgtPill-wifiAps`) and
    `Client WiFi` (`#fgtPill-wifiClients`).
  - `Localizzazione Endpoint` → MAC Tracker for the wired check.

- **App Features Present**:
  - `GET /api/wlc/{ip}/rogue-aps` ([routers/wlc.py:70](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/wlc.py#L70))
  - `GET /api/fortigate/{ip}/wifi/aps` ([routers/fortigate.py:356](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L356)),
    `GET /api/fortigate/{ip}/wifi/clients` (L352) — there is no `/managed-aps` route
  - **MCP**: `wlc_rogue_aps`, `fortigate_managed_aps` (→ `/wifi/aps`), `fortigate_wifi_clients`

- **Missing Features / Gaps**:
  - **Active Rogue Containment**: no deauth / wireless containment trigger from the app.
  - **Wired Rogue Auto-Block**: no automatic port disable for a rogue MAC seen on a switch (manual path:
    MAC Tracker → Diagnosi → bounce or isolate).

---

## 4. Traffic Anomalies, Top Talkers & Session Drain

### Q4.1: A subnet shows high latency. How to find top talkers and detect anomalies?

- **Answer**:
  1. Query top talkers for the window and metric (bytes/packets).
  2. Inspect the protocol distribution and the flow detail rows.
  3. Check correlated anomalies for the same window and set their status (new / acknowledged / resolved).
  4. Query FortiGate live sessions for the offending host.
  5. Mitigate. IP shun exists as `POST /api/flow-siem/shun-ip` but has **no UI button**; verify with
     `GET /api/flow-siem/shun-list`.

- **UI Navigation & Operational Workflow**:
  - **Tab** `Traffico` (`navInvestigate` -> `#tab-flows`). Since 2026-08-11 it is **one tab with four
    views**; the twin tab `#tab-flow-siem` no longer exists.
  - **Header, shared by every view**: window `#trafWindow` (15m/1h/24h/7d, default `1h`), metric
    `#trafMetric`, tenant dropdown `#trafTenantBtn` / `#trafTenantDropdown` / `#trafTenantAll` /
    `#trafTenantList`, refresh (`trafRefresh()`), `#trafAutoRefresh`, `#trafHideTelemetry`,
    `#trafLastUpdate`, `analyzeFlowsWithAi()`. One window and one tenant selection drive all four
    views — there is no per-panel window any more.
  - **View pills** `#trafPill-overview|flows|search|anomalies` (`trafSwitchView(view)`) switching panes
    `#trafPane-overview|flows|search|anomalies`. Only the view being opened loads.
  - **Panoramica**: banner `#flowsObsBanner`, KPI strip `#fgKpiStrip`, top talkers
    `#fgTalkersTableBody`, protocol card `#obsProtocolCanvas` (donut/bar/trend +
    `openObsInspectModal()`), protocol table `#fgProtoTableBody`, tenant summary `#fgTenantSummary`.
  - **Flussi**: source chips `#flowsSourceChips`, columns `#flowsColsBtn`/`#flowsColsDropdown`, table
    `#flowsTableHead`/`#flowsTableBody`, syslog section `#flowsSyslogAllSection`, detail drawer
    `#flowDetailPanel`.
  - **Ricerca** (the former Flow SIEM): `#flowSiemStreamBadge`, `#btnFlowSiemStream`,
    `#flowSiemHistCanvas`, `#flowSiemQueryInput`, `#flowSiemFacets`, `#flowSiemTableBody`, plus
    `#flowSiemScopeNote` — `/api/flow-siem/*` scopes to a single tenant server-side, so with more than
    one tenant ticked the view says on screen that it is showing the caller's whole scope.
  - **Anomalie**: `#anomStatus`, `#anomTableBody`, `#anomIpFilterChip`, `loadAnomalies()`. Each row
    links to its incident (`anomOpenIncident()`) — the `id` returned by `/api/observability/anomalies`
    **is** the incident id, because that route selects `FROM incidents`.

- **App Features Present**:
  - `GET /api/observability/top` ([routers/observability.py:78](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/observability.py#L78)) — top talkers
  - `GET /api/observability/protocol-distribution` (L115), `GET /api/observability/syslog` (L274),
    `GET /api/observability/events` (L295), `GET /api/observability/flowgraph` (L412)
  - `GET /api/observability/anomalies` (L340), `POST /api/observability/anomalies/{event_id}/status`
    (L382) — the latter is flagged `deprecated=True` in the decorator and delegates to
    `POST /api/incidents/{id}/status`; the Traffico tab calls the incidents route directly
  - Flow SIEM (prefix `/api/flow-siem`, [routers/flow_siem.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/flow_siem.py)):
    `GET /events` (L178), `GET /histogram` (L242), `GET /facets` (L288), `POST /alerts/suppress` (L341),
    `POST /shun-ip` (L379), `GET /shun-list` (L390)
  - **MCP**: `get_top_talkers` (→ `/api/observability/top`), `get_anomalies`
    (→ `/api/observability/anomalies`) — **both disabled by default**
  - **UI**: `static/js/observability.js`, `static/js/flow-analytics.js`

- **Missing Features / Gaps**:
  - **Shun IP UI**: no dashboard button wired to `/shun-ip`.
  - **ACL / Null-Route / BGP Flowspec Injection**: no one-click block on routers.
  - **Encrypted Traffic Analysis**: L3/L4 + IPFIX/sFlow only; no TLS ClientHello SNI or JA3 extraction.

---

### Q4.2: FortiGate CPU at 95% from session-table saturation. How to find session hogs and drain them?

- **Answer**:
  1. Check the overview tiles (Hostname, FortiOS, HA, CPU, Memoria, Disco, Sessioni) and the resources
     series.
  2. Filter sessions by the suspect source IP.
  3. Check per-policy hit counts and active sessions to see which rule carries the load.
  4. Look for states typical of SYN flood or half-closed connections.
  5. Drain: `DELETE /api/fortigate/{ip}/sessions` via `#btnFgtSessionKill`, or
     `diagnose sys session clear` via `POST /api/send-command` / MCP `send_cli_command`. There is no
     CLI console button **in this tab** (the WS terminal lives in the device inventory).

- **UI Navigation & Operational Workflow**:
  - Pane **Panoramica** (`#fgtSub-overview`): status tiles + `#fgtView-resources` + `#fgtView-ha`.
  - Pane **Traffico** → pill **Sessioni**: `#fgtSessSrc`, `#fgtSessDst`, `#fgtSessPort`, load
    `#btnFgtSessLoad`, kill `#btnFgtSessionKill` (refuses to run with all three filters empty, which
    would have killed every session).
  - Pane **Firewall** → pill **Policy** (`#fgtPill-policies`): hit counts / active sessions / last used
    / static findings.
  - There is **no** `#btnOpenCli`.

- **App Features Present**:
  - `GET /api/fortigate/{ip}/status` (L155), `/system/resources` (L159), `/system/ha` (L164)
  - `POST` / `DELETE /api/fortigate/{ip}/sessions` (L311 / L318)
  - `GET /api/fortigate/{ip}/policy-stats` (L212), `/firewall/policies-with-stats` (L257)
  - `POST /api/send-command` ([routers/commands.py:161](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/commands.py#L161)),
    `POST /api/bulk-command` (L210), `GET /api/bulk-command/{job_id}` (L267), `POST /api/ws-token` (L286),
    `WS /api/ws-terminal/{ip}` (L326)
  - **MCP**: `fortigate_status`, `fortigate_sessions`, `fortigate_policy_stats`, `send_cli_command`

- **Missing Features / Gaps**:
  - **CLI Console UI in this tab**: no embedded console on the FortiGate tab (session kill got its
    button on 2026-08-11).
  - **Session Threshold Alerts**: no webhook/paging when session utilisation crosses a threshold.

---

## 5. Incident Response, Flow SIEM & AI Narrative

### Q5.1: An alert suggests a port scan or C2 beaconing from `192.0.2.77`. How to triage?

- **Answer**:
  1. Open the incident record (`GET /api/incidents`, filtered by status and window).
  2. Read the detail: fired rules, corroborating sources, evidence by role, confidence, timeline, flow
     path, previous conclusions.
  3. Corroborate with observability anomalies for the same IP and with global triage status.
  4. Locate the host's MAC/port (§2) or run the full client report (§9).
  5. Generate the AI narrative: `POST /api/incidents/{incident_id}/explain`.

- **UI Navigation & Operational Workflow**:
  - **Tabs**: `Incidenti` (`#navIncidents` → `#tab-incidents`, admin-only, preview) and `AI Assistant`
    (`#tab-ai`).
  - **Incidents**: list `#incidentsList` (not a table body), filters `#incStatusFilter` /
    `#incWindowFilter`, detail `#incidentDetail`, Ack/Resolve via `setIncidentStatus(id, from, to)`,
    AI block `#incidentAiBody` (rendered by `incidents.js`, filled by `explainIncident(id)`).
    There are **no** `#btnRunIncidentTriage` / `#btnAiDiagnoseIncident` buttons.
  - **AI Assistant**: `#aiConvList`, `#aiChatMessages`, `#aiChatInput`, `#btnAiSend` (`sendAiChat()` →
    `POST /api/ai/chat`), attachments `#aiAttachDeviceBtn` / `#aiAttachTenant`.

- **App Features Present**:
  - Incidents (prefix `/api/incidents`, [routers/incidents.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/incidents.py)):
    `GET ""` (L242), `GET /{id}` (L283), `POST /{id}/status` (L321), `POST /{id}/explain` (L397),
    `GET /rules` (L42), `POST /rules/{rule_id}/parameters` (L52), `GET /interfaces` (L92),
    `POST /interfaces/expected` (L177)
  - Triage ([routers/triage.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/triage.py)):
    `POST /api/run-triage` (L80), `POST /api/triage/{ip}` (L111), `GET /api/triage-status` (L125) —
    **not** `/api/triage/status`, `POST /api/ping-check` (L130), `GET /api/ping/{ip}` (L185)
  - AI ([routers/ai.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/ai.py)):
    `POST /api/ai/chat` (L509), `POST /api/ai/generate-config` (L677), profiles/conversations CRUD.
    There is **no** `/api/ai/diagnose`.
  - **MCP**: `get_triage_status`, `locate_mac`, `get_anomalies` (disabled by default)
  - **UI**: `static/js/incidents.js`, `static/js/ai.js`

- **Missing Features / Gaps**:
  - **External Threat Intel**: no AbuseIPDB / VirusTotal / OTX enrichment of flow destinations.
  - **SOAR Webhook Export**: no push of incident state to ServiceNow / Jira / Slack.

---

## 6. Security Compliance Audit & Rule Drift

### Q6.1: How to run a compliance audit on FortiGate, Cisco or Linux configurations?

- **Answer**:
  1. Run a **NetSec Audit** scan against a stored device backup **or an uploaded/pasted config**, using
     one of the shipped benchmarks: **CIS** (FortiGate 7.4.x, Cisco IOS XE 17.x, Ubuntu 24.04 LTS),
     **NIST SP 800-53 Rev. 5**, **PCI-DSS v4.0**. Output: violations with severity, category,
     remediation, guidance, a score and a grade badge.
  2. Use **Config Analyzer** for structural inspection of stored backups: policies (incl. `logtraffic`),
     objects, VLANs, routing, ACLs, interfaces; FortiOS insecure management access (http/telnet in
     `allowaccess`) is flagged, IOS SNMP communities are parsed with their ACL references.
  3. Use **Checklist Audit Firewall** — since the merge a **sub-tab of NetSec Audit**, not its own tab —
     for engagement-style audits: templates, per-item status, evidence upload, final report.
  4. Download raw backups when needed.

- **UI Navigation & Operational Workflow**:
  - **Tabs**: `NetSec Audit` (`#navNetSecAudit` → `#tab-netsec-audit`, preview badge, **not**
    admin-only — a viewer can open it) and `Config Analyzer` (`#tab-config`), both under **Valuta**.
    `#tab-audit-checklist` and `#navAuditChecklist` **no longer exist**: the checklist is the second
    sub-tab of NetSec Audit.
  - **NetSec Audit sub-tabs**: bar `#netsecSubtabNav` with `#subtabBtnAuditScan` (Scansione &
    Compliance Automatica) and `#subtabBtnChecklist` (Checklist Audit Firewall), over the panes
    `#netsecSubtabScan` / `#netsecSubtabChecklist`. `LAZY_TAB_SCRIPTS['tab-netsec-audit']` therefore
    loads **both** `netsec-audit.js` and `audit_checklist.js` (plus the html2pdf vendor bundle) —
    dropping either leaves one sub-tab dead when the tab is opened cold.
  - **Scan sub-tab controls** (markup in `dashboard.html`, populated by `static/js/netsec-audit.js`):
    benchmark `#auditBenchmarkSelect`, device `#auditDeviceSelect` (multi-device scan is *not*
    implemented — the "all" option is a placeholder), opt-in history retention `#auditSaveRun` +
    `#auditRunName`, **config upload / drag-and-drop `#auditDropZone` + `#auditFileInput` +
    `#auditDropText`** (sent as `config_text`), run `#btnRunAuditScan`, score `#auditScoreValue` +
    `#auditGradeBadge`, counters `#auditStatTotal` / `#auditStatFailed` / `#auditStatPassed` /
    `#auditStatWarned` / `#auditStatUnknown`, filters `#auditSevFilter` / `#auditCatFilter` /
    `#auditStatusFilter`, results `#auditRulesTableBody`, requirements view `#auditBenchmarkReqs` /
    `#auditBenchmarkReqsBody`, partial-coverage warning `#auditPartialWarning`, report language
    `#auditReportLang`, export `#btnExportAuditReport` (**not** `#btnPdfNetsec`, which does not exist)
    opening `#auditReportModal` / `#auditReportFrame` with `#auditModalBtnPdf` / `#auditModalBtnDoc` /
    `#auditModalBtnHtml` / `#auditModalBtnPrint`, history `#auditHistoryPanel` / `#auditHistoryBody` +
    `#btnRefreshAuditHistory`.
  - **Config Analyzer**: `#configGroupSelect`, `#caSearch`, `#caPills`, `#caResults` — auto-loads,
    no upload, no analyze button.
  - **Checklist sub-tab**: engagements `#auditEngagementList`, workspace `#auditWorkspace` /
    `#auditWorkHeader` / `#auditWorkSub`, template editor `#auditTemplateEditor`, new-audit modal
    fields `#auditCustomerName` / `#auditInterviewee` / `#auditModality`.
    There is no "Seleziona Modello Audit" select and no "Esegui Audit Checklist" button.

- **App Features Present**:
  - `GET /api/netsec-audit/benchmarks` ([routers/analyzer.py:183](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/analyzer.py#L183)),
    `POST /api/netsec-audit/scan` (L223 — accepts `device_ip` **or** `config_text`, optional
    `save: true`; an empty/missing backup is a 404, not a silently empty audit),
    `GET /api/netsec-audit/history` (L292), `GET /api/netsec-audit/history/{run_id}` (L339 — stored
    document; out-of-scope and non-existent both answer 404),
    `DELETE /api/netsec-audit/history/{run_id}` (L358, admin-only)
  - `POST /api/netsec-audit/report/pdf` (L123 — prints the preview HTML with the system browser) and
    `POST /api/netsec-audit/export/docx` (L275)
  - The scan result carries `policy_defects` from the §10 engine. It is **deliberately excluded from
    the compliance score**: a shadowed rule is a real defect but not a benchmark control, and giving
    it an invented control id would skew the one number the report is delivered for.
  - `GET /api/config-analyzer` (L52), `/{ip}` (L57), `POST /api/config-analyzer/convert` (L75)
  - Audit checklist (prefix `/api/audit-checklist`,
    [routers/audit_checklist.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/audit_checklist.py)):
    `GET /templates` (L50), `GET /templates/{id}` (L56), item CRUD (L80/L93/L106),
    `GET /engagements` (L119), `POST /engagements` (L127), `GET /engagements/{id}` (L145),
    `PATCH /engagements/{id}` (L154), `PUT /engagements/{id}/items/{ref}` (L172),
    `POST /engagements/{id}/evidence` (L191), `GET /engagements/{id}/report` (L208)
  - `GET /api/download-backup/{ip_or_filename}` ([routers/backup.py:23](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/backup.py#L23)),
    `GET /api/search` (L75)
  - **MCP**: `analyze_config`, `policy_findings`
  - **Engine**: `services/netsec_audit/`, `services/policy_test/`, `ai/config_analyzer.py`, `fw_analyzers/`

- **Missing Features / Gaps**:
  - **Git Drift Alerting**: backups are stored in-app; no auto-commit with per-line diff alerts on
    out-of-window changes.
  - **Scheduled / Recurring Audits**: scans are operator-triggered; no cron or trend of score over time.
  - *(Withdrawn: "no benchmark mapping" — CIS/NIST/PCI exist. Withdrawn: "no config upload UI" —
    NetSec Audit accepts uploads and pasted text since the drop-zone was added.)*

---

## 7. Multi-Site VPN & Routing Troubleshooting

### Q7.1: The IPsec tunnel between main site `192.0.2.1` and branch `198.51.100.1` is down. How to troubleshoot?

- **Answer**:
  1. Review sites and topology (`GET /api/sites`, `GET /api/network-map`).
  2. Check interfaces and tunnel status on the main gateway (`/interfaces`, `/vpn/tunnels`).
  3. Verify the route to `198.51.100.0/24` points at the IPsec virtual interface (`/routes`).
  4. Filter FortiGate logs with `#fgtLogType = event` for IKE negotiation errors (PSK mismatch,
     proposal mismatch).
  5. Test reachability (`POST /api/ping-check`, `GET /api/ping/{ip}`); for a remote site with an agent,
     push the command through the site agent instead.

- **UI Navigation & Operational Workflow**:
  - **Tabs**: `Sedi` (`navAdminister` → `#tab-sites`), `Fortigate Management` (`#tab-fortigate`).
  - FortiGate pane **Rete** (`#fgtSub-network`): pills `Interfacce` (`#fgtPill-interfaces`), `VPN`
    (`#fgtPill-vpn`), `Routing` (`#fgtPill-routes`), `ARP` (`#fgtPill-arp`), `DHCP` (`#fgtPill-dhcp`),
    `SD-WAN` (`#fgtPill-sdwan`).
  - FortiGate pane **Traffico** → pill `Log` with `#fgtLogType = event`.

- **App Features Present**:
  - `GET /api/sites` ([routers/sites.py:61](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/sites.py#L61) —
    a non-admin gets only `id` / `name` / `mode`; bastion address, identity, subnets and token state
    stay with the admins who configure them), site CRUD (L74/L88/L119),
    `POST /api/sites/test-bastion` (L126), `POST /api/sites/regenerate-token` (L149),
    `POST /api/sites/{site_id}/command` (L157), `GET /api/command-jobs/{job_id}` (L188),
    `GET /api/sites/{site_id}/command-jobs` (L199), agent update/restart/config/inventory/flow-control
    (L218–L301)
  - `GET /api/topology` ([routers/topology.py:55](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/topology.py#L55)),
    `GET /api/network-map` (L61) — **not** `/api/topology/map`, `POST /api/map/export/vsdx` (L67),
    `GET /api/portchannels` (L83), `POST /api/topology/reset` (L153)
  - `GET /api/fortigate/{ip}/interfaces` (L191), `/routes` (L326), `/vpn/tunnels` (L330),
    `/sdwan/health` (L336)
  - **MCP**: `list_sites`, `get_network_map`, `get_port_channels`, `fortigate_interfaces`,
    `fortigate_routes`, `fortigate_arp`, `fortigate_dhcp_leases`, `fortigate_device_inventory`
  - **UI**: `static/js/site-agent.js`, `static/js/fortigate-management.js`

- **Missing Features / Gaps**:
  - **IPsec IKE Debug Streaming**: no `diagnose debug application ike` stream; only tunnel state, logs
    and manual CLI.
  - **BGP / OSPF Neighbor Telemetry**: no parser/API for dynamic routing adjacency state.

---

### Q7.2: A remote site is only reachable through an SSH bastion. How to onboard it, and what breaks?

- **Answer**:
  1. Create the site with `mode = jump`. Beside name and subnets it needs a **bastion host/port** and
     two identities, kept separate on purpose: the one that logs into the **bastion** and the default
     one used for the **devices** behind it.
  2. Every netmiko call for a device in that site is tunnelled through the bastion
     (`core/net_ssh.py`: one cached `paramiko.Transport` per site, per-site lock, bounded connect).
  3. Test the hop before blaming the device. A refused bastion login and a refused device login both
     surface as "authentication failed" on the device row, and the operator ends up rotating the
     credential on the wrong machine. `POST /api/sites/test-bastion` answers
     `success` / `auth_failed` / `unreachable` for the **bastion**, and deliberately does **not** go
     through the cached transport: `probe_bastion()` dials fresh, so it tests the credential as it is
     configured now rather than the one a live session was opened with.
  4. Editing the bastion host, port or identity calls `net_ssh.invalidate_site(site_id)`, which closes
     and drops the cached transport. Without it an edited login changed nothing until the old session
     happened to die.
  5. *(working tree, ahead of `e8f006b`)* The bastion's SSH host key is pinned **trust-on-first-use**
     into the same `ssh_known_hosts` file the WS terminal uses. `paramiko.Transport` has no policy
     hook, so the pinned key is handed to `connect(hostkey=…)`, which refuses any other, and a first
     contact is recorded afterwards. A changed key raises `BastionHostKeyError`, whose message names
     the `known_hosts` entry (`host` on port 22, `[host]:port` otherwise) to remove if the bastion was
     genuinely rebuilt. Reconnecting anyway is not offered.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Sedi` (`navAdminister` → `#tab-sites`, admin-only). Sites table `#sitesTableBody`.
  - **Create**: `#newSiteName`, `#newSiteMode` (`central` / `agent` / `jump`), `#newSiteSubnets`,
    `#btnCreateSite`. Picking `jump` reveals `#jumpFields` — `#newSiteJumpHost`, `#newSiteJumpPort`,
    `#newSiteJumpIdentity`, `#newSiteDeviceIdentity` — and the `#jumpLimits` panel that spells the
    limitations out on screen.
  - **Edit after creation**: each jump row carries an inline
    `data-action="set-site-jump-identity"` select (the bastion identity **is** editable after the site
    exists) and a `data-action="test-bastion"` button. Both are rendered by `static/js/settings.js`,
    which `LAZY_TAB_SCRIPTS` loads for `tab-sites` as well as `tab-settings`, `tab-users` and `tab-mcp`.
  - **What does not work on a jump site** (stated in `#jumpLimits`, not only in the docs): no ICMP, so
    online/offline stays "non misurabile" rather than collapsing to *down*; no subnet scan or
    discovery; no inbound syslog/flow/SNMP; no vendor REST (FortiGate token path) — CLI only.
    Inventory, config backup, MAC/ARP, CLI commands and audits do work.

- **App Features Present**:
  - `POST /api/sites` (L74, `jump_host` / `jump_port` / `jump_identity` / `device_identity`),
    `POST /api/sites/update` (L88 — only the jump fields actually supplied are forwarded, so renaming
    a jump site cannot blank an unrelated field and fail revalidation),
    `POST /api/sites/test-bastion` (L126, admin)
  - `core/net_ssh.py`: `_dial` / `_transport` / `invalidate_site` / `probe_bastion` /
    `jump_channel` / `jump_site_for` / `ConnectHandler` / `close_all`
  - Identity store shared with provisioning push (§1.2): `GET/POST /api/identities`
  - **UI**: `static/js/settings.js`

- **Missing Features / Gaps**:
  - **Key-based bastion auth**: `_dial` authenticates with username + password from the identity
    store; there is no private-key identity type.
  - **Host-key rotation from the UI**: a changed bastion key has to be cleared by editing
    `ssh_known_hosts` on disk — the error names the entry, but nothing in the app removes it.
  - **Bastion reachability monitoring**: `test-bastion` is operator-triggered; nothing polls the hop,
    so a dead bastion is discovered by the next device operation that fails.

---

## 8. Infrastructure Health & Observability Pipeline

### Q8.1: The host running the SentinelNet collectors is degrading. How to assess it?

- **Answer**:
  1. `GET /api/observability/health` — enabled state, active listeners, metric counters, DB size,
     schema version.
  2. For polled host/device snapshots (including Linux metrics when `linux_poll_s` > 0),
     `GET /api/observability/api-context?device_ip=<host>` — this is what MCP `linux_health` calls.
     There is **no** `/api/observability/linux-health`.
  3. Verify listener configuration in Settings → Observability (bind address, API/SNMP/Linux polling).
  4. Reclaim space with `POST /api/observability/prune-logs` (`{"days": N}` — deletes `syslog_events`
     and `flow_aggregates` older than N days), from Settings → Observability.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Impostazioni` (`navAdminister` → `#tab-settings`); observability settings render into
    `#obsSettingsBody` by `static/js/observability.js`: `#obs_enabled`, `#obs_bind`, `#obs_api_poll_s`,
    `#obs_snmp_poll_s`, `#obs_linux_poll_s`, restart banner `#obsRestartBanner`, and the one-off purge
    `#obsPruneDays` + `#btnPruneObsLogs` (`data-action="prune-obs-logs"`).
  - There are **no** `#tab-obs-settings`, `#subtab-health`, `#btnPruneLogs` (the purge button is
    `#btnPruneObsLogs`), no CPU/RAM/disk KPI cards and no service badges anywhere in the dashboard.

- **App Features Present**:
  - `GET /api/observability/health` ([routers/observability.py:635](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/observability.py#L635))
  - `GET /api/observability/api-context` (L606), `POST /api/observability/api-poll` (L625)
  - `GET/POST /api/observability/config` (L561/L568)
  - `POST /api/observability/prune-logs` (L663) — one-off purge, wired to the Settings panel since
    2026-08-11; the scheduled per-table retention is `observability/rollup.py:71` `retention_loop()`
  - `GET /api/ping-monitor/status` ([routers/settings.py:179](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/settings.py#L179))
  - **MCP**: `linux_health` (→ `/api/observability/api-context`, **disabled by default**)

- **Missing Features / Gaps**:
  - *(Withdrawn 2026-08-11: "Health UI" and "no prune button" — Settings -> Observability now renders
    pipeline state (enabled, per-listener badges, DB size, schema version) from
    `GET /api/observability/health`, with a one-off purge wired to `POST /api/observability/prune-logs`.)*
  - *(Correction: pruning was never "explicit call only". `observability/rollup.py:71`
    `retention_loop()` runs periodically from the listener manager and prunes each table by its
    configured `retention_days` (Settings -> Applicazione -> Retention dati observability). The manual
    purge is an on-demand extra, not the only path.)*
  - **Size/Disk Watermark**: retention is time-based only. Nothing reacts to the DB growing past a size
    threshold — a burst inside the retention window still fills the disk.

---

## 9. Single-Client L2+L3 Diagnosis *(new — absent from both previous versions)*

### Q9.1: "User at `192.0.2.88` cannot reach `198.51.100.45`." How to get one report covering switch port, gateway, path and firewall verdict?

- **Answer**:
  1. Enter the client (IP **or** MAC) and, optionally, a destination + protocol + port.
  2. The gateway can be left on **Auto (ARP / Subnet)**, chosen from the discovered candidates, or
     detected live via traceroute first-hop.
  3. The service returns a read-only report: where the client is attached (switch, port, VLAN, trunk
     detection), port state and counters, the L3 path, the governing firewall policy and recent blocks.
  4. Scope is tenant-aware: a viewer only sees the tenants in their profile, and a tenant passed
     explicitly must be inside that scope.
  5. If the port is wedged, **Bounce porta** performs a shut / no-shut on the access port. It is
     admin-only and refuses to act on stale MAC-table data — an old entry could point at a port that
     now belongs to another host.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Diagnosi Client` (`#locPane-diagnosi`, pill `#locPill-diagnosi` under **Localizzazione
    Endpoint** / `#tab-endpoint`).
  - **Controls**: `#diagClientInput` (IP or MAC), `#diagDestInput`, gateway `#diagGatewaySelect` +
    `#diagGatewayInput` + `#btnDiagTraceroute`, `#diagProtoInput`, `#diagPortInput`, run
    `#btnRunDiagnosi`, report `#diagResult`.
  - **Actions inside the report** (delegated on `#diagResult`, all `data-action`):
    `rerun-diagnosi`, `diagnosi-pick-tenant`, `diagnose-wifi`, `diag-bounce-port`,
    `diag-isolate-port`, `diag-restore-port`.
  - **Wireless card**: `#diagWlcIp` + `data-action="diagnose-wifi"` → `#diagWifiBody`. It is manual on
    purpose: the L2/L3 diagnosis cannot know *which* controller to ask (the inventory accepts a
    generic `cisco` vendor, so a vendor-filtered list would offer every Cisco switch as if it were a
    WLC), and an SSH session to a controller should not be charged to a wired client.

- **App Features Present**:
  - `POST /api/diagnose/client` ([routers/diagnosis.py:48](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/diagnosis.py#L48)) — read-only, `get_current_user`
  - `GET /api/diagnose/gateway-candidates` (L74)
  - `POST /api/diagnose/traceroute-gateway` (L88) — scope enforced in the service, not by
    `assert_device_allowed`, because the target is not an inventory device
  - `POST /api/diagnose/port-bounce` (L103) — **admin-only, the only write in this tab**, and the only
    port action with a UI button
  - `POST /api/fortigate/{ip}/diagnose-client` ([routers/fortigate.py:366](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L366)) — the firewall-side equivalent
  - `GET /api/wlc/{ip}/diagnose-client/{mac}` ([routers/wlc.py:78](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/wlc.py#L78)) — the wireless leg, on demand
  - **MCP**: `diagnose_client` (cross-site, accepts an optional `tenant`), `fortigate_diagnose_client`
  - **Service**: `services/client_diagnosis.py`, `services/port_action.py`;
    **UI**: `static/js/diagnosi.js`

- **Missing Features / Gaps**:
  - **Historical Replay**: the report is a point-in-time snapshot; there is no "how did this client look
    an hour ago" view.
  - *(Withdrawn 2026-08-22: "Wireless Leg" — the report now carries a wireless card that calls
    `GET /api/wlc/{ip}/diagnose-client/{mac}`. It stays **manual**: the operator types the controller
    address, because it cannot be inferred, and the client MAC comes from the report above. With no
    MAC known the card says so instead of querying anything.)*
  - *(closed 2026-08-12)* **Persistent Isolation**: Isola porta shuts the access port and leaves it
    down; Riattiva porta is the way back and asks for no confirmation.

---

## 10. Offline Policy & Routing Validation *(new — landed 2026-08-19/20)*

### Q10.1: "Will `192.0.2.50` reach `198.51.100.10:443` through `switch-01`?" — without touching the device.

- **Answer**:
  1. Pick a **tenant**, then a **device**. Both are mandatory and neither is auto-selected: a flat
     device list across tenants would put several customers in one dropdown, and landing on the tab to
     find a verdict already computed for a device nobody chose reads as a statement about that device.
     Until both are chosen all three panels show a "pick one" placeholder.
  2. The engine reads the **freshest stored backup** for that IP — nothing is sent to the device — and
     parses it into a policy environment. Only `ios` and `fortios` are supported; any other config type
     is a **422**, deliberately, because routing everything else to the IOS parser produced an empty
     environment and painted a green "no defects" panel for a device that was never analysed.
  3. **Packet Tracer**: fill the flow and read the decision path (ACL in, route, ACL out / policy) with
     the rule that caught the packet at each step.
  4. **Esempi per Regola**: for each rule, a flow that matches it and a *near miss* with the reason it
     falls outside. Grouped **per rule set**, not flat: sequence numbers restart in every ACL, so two
     different "rule 10"s were indistinguishable once flattened.
  5. **Anomalie & Difetti**: the static findings, each with a witness packet you can run.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Validazione Policy & Routing` (`#navPolicyTest` → `#tab-policy-test`), under **Valuta**,
    preview badge, not admin-only. Lazy module `static/js/policy-test.js`.
  - **Selection**: `#ptTenantSelect` → `#ptDeviceSelect` (disabled until a tenant is picked, and
    empty-with-a-message when the tenant holds no devices), badges `#ptDeviceMeta` (tenant, vendor).
  - **Sub-tabs**: `#ptSubtabNav` with `#ptSubtabBtnTracer` / `#ptSubtabBtnExamples` /
    `#ptSubtabBtnFindings`, over `#ptSubtabTracer` / `#ptSubtabExamples` / `#ptSubtabFindings`.
  - **Tracer form**: `#ptSrcIp`, `#ptDstIp`, `#ptProto` (tcp/udp/icmp/ip), `#ptDport`, `#ptSport`,
    `#ptIngressIntf`, `#ptEstablished`, run `#btnPtRunTrace`, result `#ptTraceResultsContainer`.
    Choosing `icmp` reveals `#ptIcmpTypeGroup` / `#ptIcmpType` (echo request 8 by default, echo reply,
    unreachable, time exceeded, or unspecified) — without the message type, an echo rule and a reply
    rule are indistinguishable to the reader and to the model.
  - **Examples**: `#ptExamplesContainer`. Each group shows the **declaration line the device actually
    holds** — `ip access-list extended <NAME>`, `ip access-list standard <NAME>`,
    `access-list <n> (standard|extended)` *(the numbered form is the working-tree version, keyed off
    `numbered-*`)*, or `config firewall policy` — plus the interfaces the ACL is bound to and in which
    direction (`EDGE_IN on Vlan10 inbound`), and the rule set's default action.
  - **Findings**: `#ptFindingsContainer`. Each finding that is about packet coverage renders a proof
    block with the witness flow and a `data-action="prove-finding"` button writing into
    `#ptProofResult<idx>`.
  - **Listeners bind in the IIFE, not on `DOMContentLoaded`** — the module is lazy-loaded long after
    that event has fired, so a `DOMContentLoaded` handler would never run and every control would be
    silently dead. `policy-test.js` carries the comment; do not "fix" it back.

- **App Features Present**:
  - `POST /api/policy-test/{ip}/trace` ([routers/policy_test.py:81](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/policy_test.py#L81)) —
    body `src_ip`, `dst_ip`, `proto`, `sport`, `dport`, `ingress_intf`, `egress_intf`, `tcp_flags`,
    `established`, `icmp_type`
  - `GET /api/policy-test/{ip}/examples` (L140) — groups of `{name, kind, declaration, bindings,
    default_action, examples[{matching_flow, near_miss_flow, near_miss_reason}]}`
  - `GET /api/policy-test/{ip}/findings` (L177) — keys `shadowed`, `unreachable`, `any_any`,
    `route_to_nowhere`, `unresolved_object`; severity `high|medium|low|info`
  - `POST /api/policy-test/{ip}/prove` (L192) — body `{witness, expected_rule_id}`, answers
    `{proven, expected_rule_id, actual_rule_id, trace}`. The verdict is computed by the **same
    evaluator** the tracer uses, not by a second code path that would agree with the detector by
    construction, so `proven: false` is a real answer worth seeing, not an error.
  - All four are tenant-scoped through `assert_device_allowed`; all four are read-only.
  - **MCP**: `policy_trace` (`ip`, `src`, `dst`, `proto`, `dport`, `ingress`),
    `policy_findings` (`ip`) — both enabled by default.
  - **Engine**: `services/policy_test/` — `model.py` (Flow, Rule, RuleSet, RouteTable, Finding),
    `ios.py` / `fortios.py` (parsers), `engine.py` (`evaluate`), `examples.py`, `findings.py`
    (pure, zero I/O), `builtins.py`.
  - **Other surfaces of the same findings**: Config Analyzer pill **Validazione**, FortiGate pill
    **Policy** (`findings` per policy id + `shadow_analysis`), NetSec Audit `policy_defects`.

- **Missing Features / Gaps**:
  - **Vendors**: IOS and FortiOS only. Aruba, HP, PAN-OS and Junos backups get a 422 rather than a
    partial answer.
  - **Witness coverage**: a rule the parser could not read (`opaque`) or one carrying a qualifier the
    model does not evaluate (`narrowing_quals`) gets **no** witness — its coverage is unknown, so no
    packet can honestly be claimed to exercise it. Those findings show without a proof block.
  - **Freshness**: the verdict describes the stored backup, not the running config. Nothing warns that
    the backup is old, and there is no "re-fetch and re-trace" button.
  - **Multi-hop**: one device per trace. The cross-device path lives in §9's L3 path, computed by a
    different service.

---

## 11. Fleet Inventory Export & Asset Data *(new — landed 2026-08-19/21)*

### Q11.1: An auditor wants an asset list with serials, one row per physical unit, for two tenants only.

- **Answer**:
  1. Serials are collected during triage by the driver's `get_serial()` and stored alongside the
     detected version, so an export reads them from state rather than opening SSH sessions.
  2. Open the export modal, tick the tenants/sites/vendors/redundancy types and the columns, download.
  3. Ticking any **per-member** column (marked `*`) switches the export to one row per physical unit —
     a stack's or an HA pair's serials cannot share one row without being concatenated, and a
     concatenated serial cannot be filtered or looked up in a spreadsheet.
  4. Whatever is ticked, the export never widens the caller's scope: `user_group_scope` is applied
     first, the query filters narrow it further.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Rete & Dispositivi` (`#tab-devices`, under **Inventario**). Button `#btnExportDevices`
    opens `#deviceExportModal`.
  - **Modal**: filter lists `#exportFilterGroups` / `#exportFilterSites` / `#exportFilterVendors` /
    `#exportFilterRedundancy` (values `standalone`, `stack`, `ha_pair`, `sso`), column list
    `#exportColumnList` with `#btnExportColsToggle` (all/none), per-member warning
    `#exportMemberHint`, download `#btnRunDeviceExport`. Selections persist in `localStorage` under
    `sentinelnet.exportPrefs`.
  - The column list is **fetched**, never hard-coded in the frontend: the registry lives in the
    backend so the two cannot drift.

- **App Features Present**:
  - `GET /api/export/devices/columns` ([routers/inventory.py:188](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/inventory.py#L188)) —
    `{columns: [{key, header, per_member}], default}`
  - `GET /api/export/devices` (L201) — query `groups`, `sites`, `vendors`, `redundancy`, `columns`
    (comma-separated; an unknown column is a **400**, not a silently dropped one).
    Registry `_EXPORT_COLUMNS` (L144) covers hostname, ip, vendor, model, **serial**, group/tenant,
    site, version, status, profile, ssh_port, transports, the four redundancy fields, member_count,
    and the per-member `member_index|role|serial|model|state`.
    Defaults: hostname, ip, vendor, group, version, status.
  - Cells beginning `=`, `+`, `-`, `@`, tab or CR are prefixed with an apostrophe: hostname and version
    are written by the **device**, so whoever controls a device could otherwise write a formula into
    the spreadsheet of whoever exports the inventory. CSV quoting does not address this and is a
    different problem.
  - A device in no redundancy group still gets exactly one row, with the per-member columns empty,
    instead of vanishing from the export.
  - **Serial collection**: `drivers/base_driver.py:11` `get_serial()` returns `""` by default;
    implemented for Cisco IOS (`show version` → "System Serial Number", falling back to
    "Processor board ID"), FortiOS (`get system status` → "Serial-Number"), HP ProCurve
    (`show system`) and PAN-OS (`show system info`). `core/core_engine.py:378` calls it during triage
    and hands it to `services/inventory_manager.py:851`, which **keeps the previous serial when the
    new read is empty** — a failed triage must not erase what the last one learned.
  - **HA / redundancy**: `GET /api/redundancy/groups` ([redundancy/router.py:39](file:///c:/Users/vidhi/dev_ved/SentinelNet/redundancy/router.py#L39)),
    `/groups/{id}` (L45), `POST /groups` (L56), `PUT /groups/{id}` (L67), `DELETE /groups/{id}` (L84).
    Tab `#tab-redundancy` (`#navRedundancy`): KPI tiles `#haKpiTotal` / `#haKpiHealthy` /
    `#haKpiDegraded` / `#haKpiCritical`, tenant filter `#haTenantFilter`, list
    `#redundancyGroupsContainer`, create modal `#createRedundancyModal` (`#haGroupName`,
    `#haProtocol`, `#haVirtualIp`, `#haTenant`). The filter re-scopes the KPI tiles too: leaving them
    on the whole fleet while the list shows one tenant is how a degraded cluster gets attributed to
    the wrong customer. The list is fetched once and filtered client-side.

- **Missing Features / Gaps**:
  - **Serial coverage**: Aruba, Cisco CBS, Cisco WLC, Junos and Linux drivers inherit the base
    `get_serial()` and return `""` — those rows export an empty serial rather than a wrong one.
  - **Export formats**: CSV only. No XLSX, and the PDF/DOCX exporters belong to the audit report, not
    to the inventory.
  - **Scheduled export**: operator-triggered only; nothing mails or drops a nightly asset list.

### Q11.2: An operator wants a CSV of discovered/classified devices including an access point's serial and which switch port it hangs off. *(new — landed 2026-08-23, not part of this doc's 2026-08-22 verification pass)*

- **Answer**:
  1. `Dispositivi Scoperti & Classificazione` gained its own server-side export, mirroring §11.1's
     inventory export rather than sharing it: a column registry, a picker modal, and group/category
     filters, all clipped by `user_group_scope`. The old browser-side CSV builder in
     `static/js/topology.js` is gone.
  2. Two columns the inventory export does not have: **Serial** and **Neighbour Device** /
     **Neighbour Port**. An inventoried device's serial comes from scan data, same source as §11.1.
     A discovered access point's serial comes from `data/ap_inventory.json` instead, written the last
     time someone opened that AP's controller in the WLC tab — **Serial Seen At** shows how old that
     read is. An AP whose controller nobody has opened exports an empty serial; nothing queries a
     controller during the export itself.
  3. Ticking **Neighbour Device** or **Neighbour Port** switches to one row per link, same reasoning
     as §11.1's per-member columns: a device with two uplinks needs two lookable-up rows, not one
     concatenated cell. A device with no links still exports one row, with the neighbour columns
     empty. The port shown is the **neighbour's** own port — the one a technician actually patches —
     not a port on the device whose row it is.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Dispositivi Scoperti & Classificazione`. Button `#btnExportClassification` opens
    `#classificationExportModal`.
  - **Modal**: filter lists `#clsFilterGroups` / `#clsFilterCategories`, column list `#clsColumnList`,
    close `#btnCloseClassificationExport`, download `#btnRunClassificationExport`. Selections persist
    in `localStorage` under `sentinelnet.classificationExportPrefs`, a key of its own, separate from
    the inventory export's.

- **App Features Present**:
  - `GET /api/export/classification/columns` (`routers/catalog.py`) —
    `{columns: [{key, header, per_neighbour}], default}`.
  - `GET /api/export/classification` (`routers/catalog.py`) — query `columns`, `groups`, `categories`
    (comma-separated; an unknown column is a **400**). Registry `_CLASSIFICATION_COLUMNS` covers
    hostname, ip, tenant, category, subcategory, vendor, model, version, status, discovered,
    **serial**, **serial_seen_at**, **neighbour_device**, **neighbour_port**. Defaults: hostname, ip,
    tenant, category, status.
  - **AP serial collection**: the WLC tab's `overview()` (`services/wlc_service.py`) runs one bulk
    command, `show ap inventory all`, on AireOS controllers and writes an AP-name-to-serial map to
    `data/ap_inventory.json` via `services/ap_store.py`. **There is no verified IOS-XE bulk
    equivalent** (`COMMANDS["ap_inventory"]` has no `iosxe` entry in `services/wlc_service.py`), so
    the serial column is left empty by design on Catalyst 9800 controllers rather than falling back
    to one SSH round-trip per AP.
  - Same CSV-injection guard as §11.1 (`core/csv_safe.py`).

---

## 12. Per-Tenant Config Drift: History & Baseline *(new — landed 2026-08-23)*

### Q12.1: A device's config changed overnight. What changed, when, and does it still match the tenant's standard?

- **Answer**:
  1. Every config collected by `run_backup_and_triage` is now hashed (after
     per-vendor normalisation strips lines that change on their own — byte
     counts, uptime, NTP drift) and compared against the newest archived
     version for that IP. A real change archives a new version; an unchanged
     config only bumps `last_seen_at`, so "unchanged for 14 days" and "not
     collected for 14 days" read differently.
  2. **History** answers *what changed* — pick two versions, read a redacted
     unified diff.
  3. **Baseline** answers *does it match the standard* — a tenant-authored
     list of `+ must be present` / `- must be forbidden` line patterns,
     checked against the device's newest version. There is **no score, grade
     or severity**: this is not an audit. NetSec Audit (§6) already owns
     compliance scoring, benchmarks and export; the baseline answers one
     question per line, present or missing.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Config Drift` (`#navConfigDrift` → `#tab-config-drift`), under
    **Valuta**, no preview badge, not admin-only. Lazy module
    `static/js/config-drift.js`.
  - **Selection**: `#driftTenantSelect` (populated from the devices the
    caller can see); choosing a tenant renders `#driftDeviceList`, filtered
    client-side from the one `/api/drift/devices` fetch.
  - **Sub-tabs**: `#driftSubtabNav` (`#driftSubtabBtnHistory` /
    `#driftSubtabBtnBaseline`) over `#driftSubtabHistory` /
    `#driftSubtabBaseline`.
  - **History pane**: selecting a device row loads `#driftVersionsContainer`
    (hash, size, timestamp per version), then `#driftFromVersionSelect` /
    `#driftToVersionSelect` (defaulted to the two newest), `#btnDriftShowDiff`
    (disabled below two versions) renders into `#driftDiffContainer`.
  - **Baseline pane**: `#driftBaselineText` holds the tenant's raw pattern
    text, `#btnDriftSaveBaseline` (admin-only route) saves it,
    `#btnDriftSeedBaseline` appends candidate `+` rules extracted from the
    currently selected device — the operator prunes before saving, nothing is
    saved by the seed call itself. `#driftDeviationsContainer` lists the
    selected device's deviations, or a "no baseline set" placeholder when the
    tenant has none.
  - Diff text is device-supplied and rendered through `escapeHtml`, same
    convention as every other config/log surface in the app.

- **App Features Present**:
  - `GET /api/drift/devices` — every device the caller's scope can see, with
    version count, `last_change` and `last_seen`.
  - `GET /api/drift/{ip}/versions` — the version list for one device, newest
    first.
  - `GET /api/drift/{ip}/diff?from_version=&to_version=` — redacted unified
    diff (`difflib.unified_diff`, stdlib) between two archived versions,
    identified by their `seen_at` stamp. Redaction runs on each side **before**
    diffing, not on the assembled patch: `unified_diff` prefixes every line
    with `+`/`-`/a space, and the redaction patterns in
    `security/redaction.py` are anchored at line start, so a prefixed secret
    line would not match and would pass through unredacted if redacted after
    the fact.
  - `GET /api/drift/baseline/{tenant}` — the tenant's raw baseline text.
  - `PUT /api/drift/baseline/{tenant}` — replaces it (admin only, audited via
    `log_audit`).
  - `POST /api/drift/baseline/{tenant}/seed?ip=` — candidate `+` patterns
    pulled from one device's newest archived version (security-relevant
    prefixes only — AAA, SSH, SNMP, DHCP snooping, password encryption,
    portfast bpduguard, NTP/logging host, FortiOS strong-crypto/admin-lockout
    (`_SEED_PREFIXES` in `baseline.py`) — never hostname, address or VLAN,
    which differ by device by design). Saves
    nothing; admin only, same as the PUT.
  - `GET /api/drift/{ip}/baseline` — that device's deviations against its
    tenant's baseline: `{deviations: [{rule, pattern, problem}], checked}`.
    `checked: false` when the tenant has no baseline text saved yet, so the
    UI can tell "compliant" from "never evaluated".
  - All seven routes live in `routers/config_drift.py`. The four list/read
    routes are scoped through `user_group_scope`; every route naming a
    specific device goes through `assert_device_allowed` — a scoped user
    cannot read another tenant's drift by guessing an IP, same rule as every
    other device route.
  - **Storage** (`services/config_drift/history.py`): a `.history` folder
    beside the existing current backup file, keyed by IP —
    `<ip>-index.json` plus one file per retained version,
    `<name>-<ip>.<stamp>.txt`. **The current backup file's path and name are
    unchanged** — the policy test loader (§10), NetSec Audit (§6), Config
    Analyzer and `download_backup` all read that exact path, so history is
    purely additive. The stamp is UTC to microsecond precision,
    `YYYYMMDDTHHMMSS.ffffffZ`: second precision let two versions collected
    within the same second collide on both the index and the archived
    filename, silently losing the first write. **Nothing is ever pruned** —
    disk grows only when a config actually changes.
  - **Tenant moves**: `remove_stale_backups` (`core/core_engine.py`) used to
    delete every file for an IP anywhere in the backup tree. It now **moves**
    the current file and its `.history` folder together when a device
    changes tenant, instead of deleting them — re-assigning a device is a
    normal operational event, not one that should erase its archive.
  - **Git mirror** (`services/config_drift/mirror.py`), off by default, one
    app setting: when enabled, each newly archived version is also committed
    to a git repository rooted at the `.history` folder. It is **redundancy
    only** — a second copy of the archive for disaster recovery. The drift
    engine never reads from it. Enabling the mirror on a host without `git`
    on `PATH` **fails loudly** (raises, does not silently no-op) — a
    redundancy feature that is silently not running is worse than one that
    is visibly off.
  - Normalisation (`services/config_drift/normalize.py`) is vendor-specific:
    one `normalize(vendor, text)` entry point dispatching to inline pattern
    tuples (`_IOS`, `_FORTIOS`) plus a vendor-neutral set applied to
    everyone — no per-vendor module split (`services/policy_test/` splits
    its parsers into files; this package doesn't need to, the pattern lists
    are short). An unknown vendor gets only the neutral set — noisier drift,
    never a crash, never a skipped device. Normalisation applies to the hash
    and the diff only; the archived file is always the config exactly as
    collected.
  - `history.record_version` is called from `run_backup_and_triage` /
    `_fortigate_backup_and_triage` right after the existing `save_backup`
    call, wrapped in try/except at the call site — a history-recording
    failure can never fail the backup itself.

- **Missing Features / Gaps**:
  - **No restore-from-history.** Reading a past version is in scope; pushing
    it back to the device is not.
  - **No retention limit or pruning.** Every changed version is kept
    indefinitely; revisit only if a real archive grows large enough to
    matter.
  - **No alerting on drift.** The tab answers the question when asked; there
    is no notification when a device changes.
  - **No per-device variable substitution in baselines** — a rule is a
    literal or a regex against the normalised config text, nothing templated.
  - **Two vendor pattern sets only**, both inline in `normalize.py` (Cisco
    IOS/IOS-XE/WLC and FortiGate/Fortinet). Every other vendor is hashed with
    the vendor-neutral rules only.

---

## Summary Matrix of Capabilities vs Gaps (v3)

| Domain | Present App Features | Key Missing Features / Gaps |
| :--- | :--- | :--- |
| **FortiGate** | Policy lookup, sessions (+kill button), traffic/event/UTM logs, policies with hit counts, last-used **and static findings** (dead-rule marking), interfaces/ARP/DHCP/routes/VPN/SD-WAN, managed FortiAP, aggregated client diagnosis, full-config fetch, day-0 generation + push (SSH/serial/REST), REST driver with SSH fallback | Packet capture (`sniffer`), deep UTM sub-log parsing, CLI console button on this tab |
| **Cisco WLC** | Tenant-scoped controller selection, single-call `overview` (AP/clients/WLAN/rogue), 2.4 & 5 GHz auto-RF channel, width and utilization, client quality + live search, rogue table, per-client diagnostics modal **reachable from the Diagnosi report too** | Roaming (802.11r/k/v) timeline, RF floor-plan heatmap, 6 GHz auto-RF (needs the IOS-XE path), active rogue containment |
| **MAC / ARP / Endpoints** | MAC search & locate, on-demand MAC scan with per-device command overrides, ARP collection from L3 gateways, client map, endpoint inventory with exports, discovery-only subnet scan + opt-in credential verification | 802.1X/RADIUS correlation, DHCP-snooping cross-check, OS fingerprinting |
| **Client Diagnosis** | L2+L3 single-client report, gateway auto/traceroute detection, tenant-scoped, admin port bounce and persistent isolation with uplink + staleness guards, **on-demand wireless leg** | Historical replay, wireless controller still typed by hand |
| **Policy & Routing Validation** | **Offline packet tracer, per-rule matching + near-miss examples with the real ACL declaration and bindings, ICMP message types, static findings (shadowed / unreachable / any-any / route-to-nowhere / unresolved object) each with a witness packet and a `prove` verdict, surfaced in four places + 2 MCP tools** | IOS & FortiOS only (422 otherwise), no witness for opaque or narrowed rules, no backup-freshness warning, single-device traces |
| **Flow SIEM & Anomalies** | Top talkers, protocol distribution, flow graph, syslog/events, anomaly triage with status, Flow SIEM events/histogram/facets/suppression, shun API | Shun UI button, ACL/Flowspec auto-injection, JA3/SNI inspection, external threat intel |
| **Config & Compliance** | Config Analyzer (structural, FortiOS↔PAN-OS converter, Validazione view), NetSec Audit with CIS/NIST 800-53/PCI-DSS v4.0, config upload, saved-run history and PDF/DOCX/HTML report, **checklist engagements now a sub-tab of it**, backup storage/download | Scheduled/recurring audits with score trend, policy-object provisioning form, transactional push with rollback, findings not used as a provisioning pre-flight |
| **Config Drift** | **Per-tenant version history (no pruning) with redacted diffs, per-vendor normalisation so noise doesn't archive, rule-based baseline (present/forbidden) with seeding from a device, optional git mirror for archive redundancy, tenant move carries the archive instead of deleting it** | No restore-from-history, no retention limit, no drift alerting, no per-device variable substitution in baselines, only Cisco IOS/WLC and FortiGate normalised (others hashed raw) |
| **Multi-site & Bastion** | Central-poll, site-agent and **jump (SSH bastion)** modes, per-site cached transport with invalidation on edit, `test-bastion` probe, TOFU host-key pinning *(working tree)*, on-screen list of what a jump site cannot do | Key-based bastion auth, host-key rotation from the UI, no bastion reachability monitoring |
| **Inventory & Assets** | **Customizable CSV export (column registry, group/site/vendor/redundancy filters, per-member row explosion, formula-injection neutralised), serial collection on IOS/FortiOS/ProCurve/PAN-OS**, HA & redundancy groups incl. Cisco SSO with a tenant filter | Serial unread on Aruba/CBS/WLC/Junos/Linux, CSV only, no scheduled export |
| **Incidents & AI** | Rule-based incident engine (reasoning, evidence, timeline, status), AI narrative per incident, AI Assistant chat with device/tenant attachments, triage & ping endpoints | External threat-intel enrichment, SOAR webhook export |
| **Observability / Health** | Pipeline health panel, per-device REST snapshots, listener configuration, one-off purge button + scheduled per-table retention, ping monitor status | Auto-purge on a size watermark, service badges |
| **MCP surface** | **45 tools** in `ai/mcp_server.py`, per-tool enable/disable via `/api/mcp/settings` | `get_top_talkers`, `get_anomalies`, `linux_health` disabled until an admin enables them |
