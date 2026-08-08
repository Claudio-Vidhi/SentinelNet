# Network Security Operational Triage & Troubleshooting Q&A Guide — CORRECTED

> **Status**: Corrected version of `netsec_troubleshooting_qa.md`, verified against the codebase on 2026-08-08.
> Every API route, MCP tool, and UI element below was checked against `routers/`, `ai/mcp_server.py`, `templates/dashboard.html`, and `static/js/`.

## Honest verdict on the original document

**Partially correct, with significant factual errors.** Specifically:

- ✅ **Correct**: overall scenario structure; navigation groups (Indaga / Inventario / Valuta / Modifica / Amministra) and top-level tabs; most FortiGate read routes; the entire Cisco WLC section (routes + UI IDs); ARP collection controls; all MCP tool *names*; `POST /api/send-command`, `POST /api/arp/scan`, `POST /api/observability/prune-logs`, `GET /api/sites`.
- ❌ **~10 API routes that do not exist**: `/api/fortigate/{ip}/managed-aps`, `/api/mac/mac-to-ip`, `/api/mac/client-map`, `/api/endpoint-inventory`, `/api/flow-siem/top-talkers`, `/api/flow-siem/anomalies`, `/api/analyzer/config`, `/api/triage/status`, `/api/ai/diagnose`, `/api/observability/linux-health`, `/api/observability/status`, `/api/topology/map`, `/api/provisioner/generate-fortigate-config`.
- ❌ **~25 UI element IDs that do not exist** (`#btnPolicyLookupGo`, `#btnFgtSessionsFilter`, `#btnFgtSessionKill`, `#btnOpenCli`, `#subtab-*` family, `#macSearchInput`, `#btnPortIsolate`, `#flowsWindowSelect`, `#btnFlowsRefresh`, `#flowsTopTalkersBody`, `#btnShunIp`, `#incidentsTableBody`, `#btnRunIncidentTriage`, `#btnAiDiagnoseIncident`, `#configSelectBackup`, `#btnAnalyzeConfig`, `#inputFileConfig`, `#btnProvFgt`, `#tab-obs-settings`, `#subtab-health`, `#btnPruneLogs`, `#subtab-fortiap`, …). The FortiGate tab is built from panes `fgtSub-*` + view pills `fgtPill-*`, not `subtab-*`.
- ❌ **MCP file location wrong**: tools are registered in `ai/mcp_server.py` (`TOOLS` dict), not `routers/mcp.py` (which only exposes `/api/mcp/settings` and `/api/mcp/tool-config`). Note also that `get_top_talkers`, `get_anomalies`, `linux_health` are **disabled by default** (`_MCP_DEFAULT_DISABLED`).
- ❌ **3 "gap" claims are false** (the features exist): policy hit-count telemetry (`/api/fortigate/{ip}/firewall/policies-with-stats`), PCI-DSS/CIS/NIST benchmark mapping (NetSec Audit module), automated config push (provisioner push-ssh / push-serial / fgt push via REST+SSH fallback).
- ❌ **4 API-only features described as having UI buttons**: session kill (`DELETE /api/fortigate/{ip}/sessions`), IP shun (`POST /api/flow-siem/shun-ip`), port isolation (`POST /api/mac/port-control`), log pruning (`POST /api/observability/prune-logs`) have **no UI wiring** — they are real gaps that the original doc listed as present features.

---

## Overview & System Context

SentinelNet provides network security observability, triage, and configuration auditing across multi-vendor infrastructure including Fortinet FortiGate firewalls, Cisco Wireless LAN Controllers (AireOS and Catalyst 9800), campus switches (Cisco, Aruba, HP), and Linux server infrastructure.

This document formulates operational troubleshooting scenarios, step-by-step resolution workflows, UI navigation procedures, existing SentinelNet features, and identified capability gaps for Network Security Engineers.

---

## 1. Firewall Policy Triage & Traffic Inspection

### Q1.1: User reports outbound web traffic to destination `198.51.100.45:443` is being dropped by core firewall `192.0.2.1`. How to diagnose policy evaluation and rule match?

- **Answer**:
  1. Perform dry-run policy lookup on target FortiGate via API using source IP `192.0.2.105`, destination `198.51.100.45`, protocol `TCP`, and destination port `443`.
  2. Inspect returned matched policy fields (policy ID, action, source/destination interfaces, service, NAT, status).
  3. Query FortiGate active session table filtered by source IP `192.0.2.105` and destination IP `198.51.100.45` to verify whether a session exists and inspect protocol/ports/policy ID/duration.
  4. Query FortiGate traffic log stream for recent log entries matching the target source/destination pair to check log action and policy ID.
  5. Validate static routing path on FortiGate for `198.51.100.45` (Routing view) to verify the egress interface matches the expected policy source/destination interface pair.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Fortigate Management` (`#navFortigate` -> `#tab-fortigate`) under **Inventario** (admin-only).
  - **Structure**: The tab is organized in panes `#fgtSub-overview` (Panoramica), `#fgtSub-network` (Rete), `#fgtSub-firewall` (Firewall), `#fgtSub-traffic` (Traffico), `#fgtSub-security` (Sicurezza), `#fgtSub-wifi` (WiFi), `#fgtSub-settings` (Impostazioni); each pane contains view pills `#fgtPill-*` and a shared `Aggiorna` button (`refreshFgtView()`). Target selector: `#fgtTargetSelect`.
  - **Policy Lookup**: pane **Firewall** -> pill `Verifica Policy` (`#fgtPill-policyLookup`) -> form `#fgtForm-policyLookup` with inputs `Source` (`#fgtLookupSrc`), `Destination` (`#fgtLookupDst`), `Protocol` (`#fgtLookupProto`: TCP/UDP/ICMP), `Dest port` (`#fgtLookupPort`), `Interface` (`#fgtLookupIntf`) -> run button (no ID, `onclick="loadFgtDataset('policyLookup')"`, i18n key `btnFgtLookupRun`, label "Verifica policy").
  - **Sessions**: pane **Traffic** -> pill `Sessioni` (`#fgtPill-sessions`) -> form `#fgtForm-sessions` with inputs `Source` (`#fgtSessSrc`), `Destination` (`#fgtSessDst`), `Dest port` (`#fgtSessPort`) -> load button (no ID, `onclick="loadFgtDataset('sessions')"`, i18n key `btnFgtSessLoad`, label "Carica sessioni").
  - **Traffic Logs**: pane **Traffic** -> pill `Log` (`#fgtPill-logs`) -> form `#fgtForm-logs` with selects `Log Device` (`#fgtLogDevice`: disk/memory), `Log Type` (`#fgtLogType`: traffic/event/utm), `Log Subtype` (`#fgtLogSubtype`: forward/local/virus/webfilter/ips) plus filters `#fgtLogSrc`, `#fgtLogDst`, `#fgtLogAction`, date range `#fgtLogSince`/`#fgtLogUntil`, row count `#fgtLogCount` -> load button (no ID, `onclick="loadFgtDataset('logs')"`, i18n key `btnFgtLogLoad`, label "Carica log").
- **Workflow Step-by-Step**:
    1. Click **Fortigate Management** in left navigation bar under **Inventario**.
    2. Choose target firewall `192.0.2.1` from `#fgtTargetSelect` dropdown.
    3. Open pane **Firewall**, click pill **Verifica Policy**. Fill `#fgtLookupSrc` (`192.0.2.105`), `#fgtLookupDst` (`198.51.100.45`), `#fgtLookupPort` (`443`) and click the run button. Review matched policy key/value output.
    4. Open pane **Traffic**, pill **Sessioni**. Enter `192.0.2.105` in `#fgtSessSrc` and click "Carica sessioni" to verify active sessions.
    5. Click pill **Log**. Keep `#fgtLogDevice` on `disk`, `#fgtLogType` on `traffic`, `#fgtLogSubtype` on `forward`, and click "Carica log" to inspect dropped traffic entries.

- **App Features Present**:
  - **API Route**: `POST /api/fortigate/{ip}/policy-lookup` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L264-L270))
  - **API Route**: `POST /api/fortigate/{ip}/sessions` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L272-L277))
  - **API Route**: `DELETE /api/fortigate/{ip}/sessions` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L279-L285)) — **API-only: no UI button is wired to this route**
  - **API Route**: `POST /api/fortigate/{ip}/logs` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L302-L311))
  - **MCP Tools**: `fortigate_policy_lookup`, `fortigate_sessions`, `fortigate_traffic_logs`, `fortigate_policies` ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py))
  - **UI Module**: FortiGate Management tab (`static/js/fortigate-management.js`, views registered in `FGT_DATASETS`)

- **Missing Features / Gaps**:
  - **Live Packet Capture**: No integration with the CLI sniffer (`diagnose sniffer packet`) to capture raw packets from the UI.
  - **UTM Detailed Event Breakdown**: Log view returns traffic/event log rows; deep UTM sub-log fields (Application Control, Antivirus, SSL Inspection failure reasons) are not parsed into dedicated structured cards.
  - **Session Kill UI**: `DELETE /api/fortigate/{ip}/sessions` exists but no UI button exposes it (operators must call the API or use MCP/CLI).
  - *(Removed from original: "Policy Hit Count Telemetry" — this feature **exists**: the Policy pill uses `GET /api/fortigate/{ip}/firewall/policies-with-stats` and renders `hit_count`, `active_sessions`, `last_used` columns.)*

---

### Q1.2: A firewall rule update was requested for host `192.0.2.50` requiring access to SSH (`22`) and HTTPS (`443`) on `198.51.100.20`. How to verify existing objects and generate compliant FortiOS configuration?

- **Answer**:
  1. Open **Config Analyzer** to inspect objects parsed from the stored FortiGate backup (address objects, services, policies) and verify whether objects matching `192.0.2.50` and `198.51.100.20` already exist (use the search filter).
  2. Note that the **Provisioning** tab generates **day-0 bootstrap configurations** (management/WAN/LAN interfaces, DHCP, DNS, SNMPv3, AAA, hardening flags) — it does **not** generate individual policy blocks from source/destination/service forms. Single-policy changes are currently a manual CLI activity informed by the Config Analyzer output.
  3. Review generated FortiOS CLI for the day-0 config (`config system interface`, `config firewall policy` LAN→WAN, hardening) and verify logging and admin-access hardening settings.
  4. Deliver via download (.txt), SSH push, serial/console push, or FortiGate REST API push (with SSH fallback).

- **UI Navigation & Operational Workflow**:
  - **Tabs**: `Config Analyzer` (`navAssess` -> `#tab-config`) & `Provisioning` (`navChange` -> `#tab-provisioning`, requires-write).
  - **Config Analyzer controls**: tenant/group filter `#configGroupSelect`, results container `#caResults`, search filter `#caSearch`, view pills `#caPills` (Home / Firewall / Server / VLAN / Routing / ACL / Interfacce / Converti). Analysis loads automatically from `GET /api/config-analyzer?group=<group>` on tab open/refresh — there is **no** `#configSelectBackup` select, **no** `#btnAnalyzeConfig` button, and **no** config file upload control. Per-device backup freshness is shown next to a triage bolt button that refreshes the backup.
  - **Provisioning controls**: vendor section forms — FortiGate day-0 fields (`#fgtMgmtIf`, `#fgtMgmtIp`, `#fgtWanIf`, `#fgtWanMode`, `#fgtLanIf`, DNS/NTP/Syslog/SNMPv3/AAA fields, hardening checkboxes) or Cisco switch fields (`#provHostname`, `#provRole`, VLAN/port fields) -> buttons `#btnProvGenerate` ("Genera Config"), `#btnProvDownload` ("Scarica .txt"), delivery mode select `#provDeliveryMode`. There is **no** `#btnProvFgt` subtab button and **no** Source/Destination subnet + Service Ports policy form.
- **Workflow Step-by-Step**:
    1. Click **Config Analyzer** under **Valuta**; pick the tenant in `#configGroupSelect` and search the parsed FortiGate objects for `192.0.2.50` / `198.51.100.20`.
    2. If a day-0 bootstrap is needed instead, click **Provisioning** under **Modifica** and fill the FortiGate section.
    3. Click **Genera Config** to render the FortiOS CLI, review `logtraffic`/hardening lines in the preview.
    4. Click **Scarica .txt** or choose a delivery mode (SSH / serial / REST API push where configured).

- **App Features Present**:
  - **API Route**: `GET /api/config-analyzer` ([routers/analyzer.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/analyzer.py#L44-L47)) — device analyses grouped by tenant
  - **API Route**: `GET /api/config-analyzer/{ip}` ([routers/analyzer.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/analyzer.py#L49-L62))
  - **API Route**: `POST /api/config-analyzer/convert` ([routers/analyzer.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/analyzer.py#L64-L92)) — FortiOS <-> PAN-OS conversion
  - **API Routes**: `POST /api/provisioner/fgt/generate` (L221), `POST /api/provisioner/fgt/download` (L230), `POST /api/provisioner/fgt/push-ssh` (L245 — REST API first when a token is stored, SSH fallback), `POST /api/provisioner/fgt/push-serial` (L281), plus Cisco equivalents `POST /api/provisioner/generate` (L152), `/api/provisioner/download` (L162), `/api/provisioner/push-ssh` (L177), `/api/provisioner/push-serial` (L199), `GET /api/provisioner/serial-ports` (L216) ([routers/provisioner.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/provisioner.py))
  - **MCP Tools**: `generate_fortigate_config` (calls `/api/provisioner/fgt/generate`), `generate_switch_config` (calls `/api/provisioner/generate`), `analyze_config` (calls `GET /api/config-analyzer/{ip}`) ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py))
  - **UI Modules**: `static/js/config-analyzer.js`, `static/js/provisioning.js`

- **Missing Features / Gaps**:
  - **Policy-Object Provisioning Form**: No UI/API to generate a single policy block from (src subnet, dst subnet, services, src/dst interface, action) parameters — the provisioner is day-0 bootstrap only.
  - **Transactional Push With Validation/Rollback**: Push mechanisms exist (SSH Netmiko, serial console, FortiGate REST API) but there is no commit-verification/auto-rollback on failure or connectivity loss.
  - **Shadow Policy Detector**: Provisioner/analyzer does not check whether a higher-priority rule already permits or denies the traffic pattern before suggesting a new policy.

---

## 2. Campus Network MAC Tracing & Rogue Host Isolation

### Q2.1: Security alert flags suspicious MAC address `AA:BB:CC:DD:EE:FF`. How to locate physical switch port, connected VLAN, and resolved IP address across campus switches?

- **Answer**:
  1. Initiate MAC search for `AA:BB:CC:DD:EE:FF` across indexed network devices.
  2. System queries MAC address tables across access, distribution, and core switches using the configured collectors/drivers.
  3. Results are grouped by switch; trunk/uplink matches are presented alongside edge ports so the operator can isolate the access port (e.g., `switch-01` port `GigabitEthernet1/0/14`, VLAN 10).
  4. Resolve MAC to IP using the Client Map (ARP tables of L3 gateways/firewalls): `GET /api/arp/search` / `GET /api/arp/client-map`.
  5. If containment is required, administratively shut the port via `POST /api/mac/port-control` (API/MCP only — there is no UI button).

- **UI Navigation & Operational Workflow**:
  - **Tabs**: `Localizzazione Endpoint` (`navInvestigate` -> `#tab-mac`) with subtabs `#tab-mac` (MAC Tracker), `#tab-clientmap` (Client Map), `#tab-diagnosi`, `#tab-endpoints` (Inventario Endpoint).
  - **MAC Tracker controls**: "Cerca MAC" panel with inputs `MAC` (`#macSearchMac` — also partial/OUI), `VLAN` (`#macSearchVlan`), `Interface/Port-channel` (`#macSearchIface`), switch select (`#macSearchSwitch`); search button (no ID, `onclick="macSearch()"`, i18n key `btnMacSearchGo`, label "Cerca"); reset button (`macSearchReset()`); results grouped by switch in `#macResults`; stats chip `#macStats`.
  - **Client Map**: `#tab-clientmap` renders MAC↔IP bindings from gateway ARP tables cross-referenced with tracker ports.
- **Workflow Step-by-Step**:
    1. Click **Localizzazione Endpoint** in left navigation bar under **Indaga**.
    2. Enter MAC address `AA:BB:CC:DD:EE:FF` in `#macSearchMac` and click **Cerca**.
    3. Review results grouped per switch to locate access switch (`switch-01`), edge port (`GigabitEthernet1/0/14`), and VLAN tag.
    4. Click the **Client Map** subtab to resolve the MAC to its IP binding (`192.0.2.88`).
    5. To isolate the host, call `POST /api/mac/port-control` (e.g., via the MCP `send_cli_command` tool or a direct API call) with the switch IP, port `Gi1/0/14`, and action `shutdown`. **There is no "Isola Porta" button in the UI.**

- **App Features Present**:
  - **API Route**: `GET /api/mac/locate` ([routers/mac.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mac.py#L158-L188))
  - **API Route**: `GET /api/mac/search` ([routers/mac.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mac.py#L139-L156))
  - **API Route**: `POST /api/mac/port-control` ([routers/mac.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mac.py#L241-L255)) — **API/MCP-only, no UI wiring**
  - **API Route (MAC->IP)**: `GET /api/arp/search` ([routers/arp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/arp.py#L53-L60)) — there is no `/api/mac/mac-to-ip` route
  - **API Route (Client Map)**: `GET /api/arp/client-map` ([routers/arp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/arp.py#L62-L83)) — there is no `/api/mac/client-map` route
  - **MCP Tools**: `locate_mac`, `search_mac`, `mac_to_ip` (calls `/api/arp/search`), `client_map` (calls `/api/arp/client-map`) ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py))
  - **UI Modules**: `static/js/client-map.js`

- **Missing Features / Gaps**:
  - **802.1X / RADIUS Telemetry Integration**: Does not pull RADIUS authentication history (username, EAP method, posture state) associated with a MAC address from Cisco ISE or FreeRADIUS.
  - **Port Isolation UI**: `POST /api/mac/port-control` has no button anywhere in the dashboard.

---

### Q2.2: An unassigned IP range `192.0.2.128/25` shows abnormal activity. How to execute ARP discovery and populate endpoint inventory?

- **Answer**:
  1. Trigger ARP table collection against the selected L3 gateways/firewalls for the tenant.
  2. Aggregate returned ARP bindings (IP, MAC, interface, gateway).
  3. Cross-reference discovered endpoints against the endpoint inventory (`GET /api/endpoints/list`).
  4. Flag uncataloged IP/MAC bindings as unknown hosts.
  5. Results are stored for temporal analysis.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Localizzazione Endpoint` -> subtab **Client Map** (`#tab-clientmap`) — the ARP collection panel lives in the Client Map tab, **not** in `#tab-mac` — and subtab **Inventario Endpoint** (`#tab-endpoints`).
  - **Buttons & Controls**:
    - Select: `Filtra per Tenant` (`#arpScanGroup`) / Multi-select: gateway menu (`#arpDeviceMenu`)
    - Button: `<i class="fa-solid fa-satellite-dish"></i> Raccogli ARP (gateway L3)` (`#btnArpScan`, `onclick="runArpScan()"`)
    - Inputs: `MAC` (`#arpSearchMac`), `IP (anche prefisso)` (`#arpSearchIp`) -> search button (`onclick="arpClientSearch()"`)
    - KPIs: `#kpiArpBindings`, `#kpiArpUniqueMacs`, `#kpiArpGateways`
    - Subtab: `Inventario Endpoint` (`#tab-endpoints`) -> table filters & export
- **Workflow Step-by-Step**:
    1. Click **Localizzazione Endpoint** in left nav bar and open the **Client Map** subtab.
    2. Select the tenant in `#arpScanGroup` and check the gateway routers/firewalls in `#arpDeviceMenu`.
    3. Click **Raccogli ARP (gateway L3)** to execute live ARP table gathering.
    4. Enter prefix `192.0.2.128.` in `#arpSearchIp` and run the search.
    5. Switch to **Inventario Endpoint** to inspect cataloged bindings vs unknown hosts.

- **App Features Present**:
  - **API Route**: `POST /api/arp/scan` ([routers/arp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/arp.py#L21-L51))
  - **API Route**: `GET /api/endpoints/list` and `GET /api/endpoints/ports` ([routers/endpoint_inventory.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/endpoint_inventory.py#L35-L52)) — there is no `/api/endpoint-inventory` route
  - **MCP Tool**: `arp_scan` ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py))
  - **UI Module**: `static/js/endpoint-inventory.js`

- **Missing Features / Gaps**:
  - **Active OS Fingerprinting**: ARP-table based discovery only; no active Nmap TCP/UDP OS fingerprinting or banner grabbing.
  - **DHCP Snooping Cross-Check**: Cannot inspect DHCP snooping databases on switches to verify ARP responses.

---

## 3. Wireless LAN Client Disconnects & Rogue AP Containment

### Q3.1: Executive user on MAC `00:11:22:33:44:55` experiences frequent Wi-Fi disconnects on Cisco WLC `192.0.2.10`. How to troubleshoot wireless health and AP association?

- **Answer**:
  1. Query Cisco WLC live status endpoint for target controller IP `192.0.2.10`.
  2. Perform client detail lookup for client MAC `00:11:22:33:44:55`.
  3. Analyze telemetry fields: connected AP name, SSID/WLAN ID, radio band, RSSI (e.g. `-78 dBm` weak signal), SNR, bytes transferred, association status.
  4. Run automated WLC client diagnostic (`/api/wlc/{ip}/diagnose-client/{mac}`) to check status flags (authentication failure, DHCP timeout, EAPOL handshake failure, low RSSI).
  5. Inspect AP summary for client density and channel utilization metrics.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Cisco WLC` (`navInventory` -> `#tab-wlc`, nav button `#navWlc`).
  - **Buttons & Controls**:
    - Target Select: `#wlcTargetSelect`
    - Button: `<i class="fa-solid fa-rotate"></i> Aggiorna` (`onclick="refreshWlcData()"`)
    - Tables: `Access Point` (`#wlcApTableBody`), `Client Wireless` (`#wlcClientTableBody`)
    - Table Action: `Diagnostica` (`onclick="wlcDiagnoseClient(mac)"`)
    - Modal Window: `#wlcDiagModal` (body `#wlcDiagModalBody`)
- **Workflow Step-by-Step**:
    1. Click **Cisco WLC** in left navigation bar under **Inventario**.
    2. Select target controller IP `192.0.2.10` from `#wlcTargetSelect` and click **Aggiorna**.
    3. Review KPI cards (controller version, AP count, client count).
    4. In the clients table, locate MAC `00:11:22:33:44:55` and check RSSI/SNR.
    5. Click **Diagnostica** next to the client row to open `#wlcDiagModal`.

- **App Features Present**:
  - **API Route**: `GET /api/wlc/{ip}/status` ([routers/wlc.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/wlc.py#L39-L41))
  - **API Route**: `GET /api/wlc/{ip}/client/{mac}` ([routers/wlc.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/wlc.py#L51-L53))
  - **API Route**: `GET /api/wlc/{ip}/diagnose-client/{mac}` ([routers/wlc.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/wlc.py#L67-L69))
  - **API Route**: `GET /api/wlc/{ip}/ap-summary` ([routers/wlc.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/wlc.py#L43-L45)); also `client-summary` (L47), `wlan-summary` (L55), `interfaces` (L63)
  - **MCP Tools**: `wlc_status`, `wlc_client_detail`, `wlc_diagnose_client`, `wlc_ap_summary`, `wlc_client_summary`, `wlc_wlan_summary` ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py))
  - **UI Module**: `static/js/wlc.js`

- **Missing Features / Gaps**:
  - **802.11 Roaming Event Timeline**: No historical log of fast roaming transitions (802.11r/k/v) between APs.
  - **AP RF Heatmap Visualization**: Tabular AP summary only; no floor-plan coverage overlay.

---

### Q3.2: Rogue Access Point detected on site premises broadcasting spoofed corporate SSID. How to locate and evaluate threat severity?

- **Answer**:
  1. Query WLC rogue AP endpoint for target WLC controller `192.0.2.10`.
  2. Parse detected rogue entries: BSSID, SSID, channel, RSSI, classification.
  3. Cross-check FortiGate-managed FortiAP telemetry (`GET /api/fortigate/{ip}/wifi/aps` and `/wifi/clients`) to see whether FortiWiFi infrastructure also observes the rogue signal.
  4. Identify detecting APs with highest RSSI to approximate physical location.
  5. Search the rogue BSSID in MAC Tracker to rule out a rogue AP wired to an internal switch port.

- **UI Navigation & Operational Workflow**:
  - **Tabs**: `Cisco WLC` (`#tab-wlc`) & `Fortigate Management` (`#tab-fortigate`).
  - **Controls**:
    - WLC table: `Rogue AP` (`#wlcRogueTableBody`)
    - FortiGate: pane **WiFi** (`#fgtSub-wifi`) with pills **FortiAP** (`#fgtPill-wifiAps`) and **Client WiFi** (`#fgtPill-wifiClients`) — there is no `#subtab-fortiap` control.
- **Workflow Step-by-Step**:
    1. Click **Cisco WLC**, select controller `192.0.2.10`, click **Aggiorna**.
    2. Review the rogue AP table (`#wlcRogueTableBody`) for BSSIDs, SSIDs, channels, RSSI.
    3. Identify the monitoring AP reporting strongest RSSI.
    4. Switch to **Fortigate Management**, select the FortiGate, open pane **WiFi** to cross-verify managed AP/client telemetry.
    5. Open **Localizzazione Endpoint** MAC Tracker and search the rogue BSSID to check wired presence.

- **App Features Present**:
  - **API Route**: `GET /api/wlc/{ip}/rogue-aps` ([routers/wlc.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/wlc.py#L59-L61))
  - **API Route**: `GET /api/fortigate/{ip}/wifi/aps` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L317-L319)) — there is no `/api/fortigate/{ip}/managed-aps` route; also `GET /api/fortigate/{ip}/wifi/clients` (L313)
  - **MCP Tools**: `wlc_rogue_aps`, `fortigate_managed_aps` (calls `/api/fortigate/{ip}/wifi/aps`), `fortigate_wifi_clients` ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py))
  - **UI Modules**: `static/js/wlc.js`, `static/js/fortigate-management.js`

- **Missing Features / Gaps**:
  - **Active Rogue Containment Trigger**: No API command to trigger deauth / wired containment from the WLC.
  - **Automated Switch Port Auto-Block for Wired Rogue**: No automatic disabling of the switch port matching a rogue MAC on the wired side.

---

## 4. Network Traffic Anomalies, Top Talkers & DDoS / Session Drain Response

### Q4.1: Internal subnet experiences high latency. How to identify top bandwidth-consuming endpoints and detect traffic anomalies?

- **Answer**:
  1. Query top talkers aggregation for the desired time window.
  2. Inspect the breakdown by source/destination/VLAN/rate (bytes or packets metric).
  3. Query anomalies for flagged traffic patterns in the same window.
  4. Perform a FortiGate live session query for the offending host to inspect active sessions.
  5. Formulate a mitigation plan (rate limiting or shun). Note: IP shun is available as an API (`POST /api/flow-siem/shun-ip`) but has **no UI button**.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Traffico` (`navInvestigate`) -> subtabs `Flussi` (`#tab-flows`, "Live Flows (Top Talkers)") and `Flow SIEM` (`#tab-flow-siem`).
  - **Controls (#tab-flows)**:
    - Window select: `#flowsWindow` (`15m` / `1h` / `24h` / `7d`) — not `#flowsWindowSelect`
    - Metric select: `#flowsMetric` (bytes / packets)
    - Tenant filter: `#flowsTenantBtn` dropdown (`#flowsTenantDropdown`, `#flowsTenantList`)
    - Refresh button (no ID, `onclick="loadTopTalkers()"`, label "Aggiorna") — not `#btnFlowsRefresh`
    - Top talkers table: `#fgTalkersTableBody` — not `#flowsTopTalkersBody`; KPI strip `#fgKpiStrip`; protocol table `#fgProtoTableBody`; flow detail table `#flowsTableBody`
    - Correlated anomalies panel: status select `#anomStatus` (Nuove / Prese in carico / Risolte / Tutte), refresh (`onclick="loadAnomalies()"`), table `#anomTableBody`, IP filter chip `#anomIpFilterChip`
  - **Controls (#tab-flow-siem)**: window `#flowSiemWindow`, tenant `#flowSiemTenant`, query input `#flowSiemQueryInput`, live stream toggle `#btnFlowSiemStream`, histogram `#flowSiemHistCanvas`, facets `#flowSiemFacets`, events table `#flowSiemTableBody`.
- **Workflow Step-by-Step**:
    1. Click **Traffico** under **Indaga**.
    2. Select `15m` in `#flowsWindow`, pick metric in `#flowsMetric`, click **Aggiorna**.
    3. Inspect `#fgTalkersTableBody` sorted by rate to identify the bandwidth hog.
    4. In the anomalies panel select `Nuove` in `#anomStatus` and review triggers.
    5. There is **no Shun IP button** in the UI; if shunning is required call `POST /api/flow-siem/shun-ip` via API/MCP and verify with `GET /api/flow-siem/shun-list`.

- **App Features Present**:
  - **API Route (top talkers)**: `GET /api/observability/top` ([routers/observability.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/observability.py#L78-L113)) — there is no `/api/flow-siem/top-talkers` route
  - **API Route (anomalies)**: `GET /api/observability/anomalies` ([routers/observability.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/observability.py#L340-L383)) + `POST /api/observability/anomalies/{event_id}/status` (L385) — there is no `/api/flow-siem/anomalies` route
  - **Flow SIEM routes** (prefix `/api/flow-siem` in [routers/flow_siem.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/flow_siem.py)): `GET /events` (L178), `GET /histogram` (L242), `GET /facets` (L288), `POST /alerts/suppress` (L341), `POST /shun-ip` (L379), `GET /shun-list` (L390)
  - **MCP Tools**: `get_top_talkers` (calls `/api/observability/top`), `get_anomalies` (calls `/api/observability/anomalies`), `fortigate_sessions` ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py)). **Note**: `get_top_talkers` and `get_anomalies` are disabled by default (`_MCP_DEFAULT_DISABLED`).
  - **UI Modules**: `static/js/observability.js`, `static/js/flow-analytics.js`

- **Missing Features / Gaps**:
  - **Shun IP UI**: `POST /api/flow-siem/shun-ip` exists but no dashboard button is wired to it.
  - **Automated ACL / Null-Route / BGP Flowspec Injection**: No one-click automated block injection on routers.
  - **Encrypted Traffic Analysis (JA3 / SNI)**: Flow collector parses L3/L4 + IPFIX/sFlow records; no TLS ClientHello SNI/JA3 extraction.

---

### Q4.2: FortiGate firewall CPU reaches 95% due to session table saturation. How to identify session hogs and drain stale connections?

- **Answer**:
  1. Check the FortiGate overview (status + system resources) to verify CPU, memory, disk, and session utilization.
  2. Query active sessions filtered by top source IP to isolate hosts creating disproportionate sessions.
  3. Inspect policy stats to identify which rule handles the session-heavy traffic.
  4. Verify whether sessions are stuck in states indicative of SYN flood or improper TCP termination.
  5. Clear sessions for the offending IP: `DELETE /api/fortigate/{ip}/sessions` (API-only) or `diagnose sys session clear` via `POST /api/send-command` / MCP `send_cli_command`. There is no CLI console button in the FortiGate tab.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Fortigate Management` (`#tab-fortigate`).
  - **Controls**:
    - Pane **Panoramica** (`#fgtSub-overview`): status tiles (Hostname, FortiOS, HA, CPU, Memoria, Disco, Sessioni) + resources view `#fgtView-resources` + HA view `#fgtView-ha` — there is no `#subtab-status` control.
    - Pane **Traffic** (`#fgtSub-traffic`) -> pill **Sessioni** (`#fgtPill-sessions`): inputs `#fgtSessSrc`, `#fgtSessDst`, `#fgtSessPort`; load button `onclick="loadFgtDataset('sessions')"`.
    - Pane **Firewall** -> pill **Policy** (`#fgtPill-policies`) shows hit counts and active sessions per policy (`/api/fortigate/{ip}/firewall/policies-with-stats`); policy counters also via pill + `GET /api/fortigate/{ip}/policy-stats`.
    - There is **no** `#btnFgtSessionKill` and **no** `#btnOpenCli` in the UI.
- **Workflow Step-by-Step**:
    1. Open **Fortigate Management**, select core firewall `192.0.2.1`.
    2. Pane **Panoramica**: verify CPU tile and `#fgtView-resources` series.
    3. Pane **Traffic**, pill **Sessioni**: enter session-hog IP `192.0.2.14` in `#fgtSessSrc`, click "Carica sessioni".
    4. Review sessions table (protocol, source/destination, ports, policy ID, duration).
    5. Drain sessions via `DELETE /api/fortigate/{ip}/sessions` (direct API/MCP) or execute `diagnose sys session clear` via `POST /api/send-command`.

- **App Features Present**:
  - **API Route**: `GET /api/fortigate/{ip}/status` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L155-L157))
  - **API Route**: `GET /api/fortigate/{ip}/system/resources` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L159-L162))
  - **API Route**: `POST /api/fortigate/{ip}/sessions` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L272-L277))
  - **API Route**: `DELETE /api/fortigate/{ip}/sessions` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L279-L285)) — **API-only, no UI button**
  - **API Route**: `GET /api/fortigate/{ip}/policy-stats` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L212-L214)) and `GET /api/fortigate/{ip}/firewall/policies-with-stats` (L226)
  - **API Route**: `POST /api/send-command` ([routers/commands.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/commands.py#L136-L176))
  - **MCP Tools**: `fortigate_status`, `fortigate_sessions`, `fortigate_policy_stats`, `send_cli_command` ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py))
  - **UI Module**: `static/js/fortigate-management.js`

- **Missing Features / Gaps**:
  - **Session Kill / CLI Console UI**: Neither a session-kill button nor an embedded CLI console exists in the tab; both actions are API/MCP-only.
  - **Automated Session Threshold Alerts**: No configurable webhook/paging alert when session utilization crosses a threshold.

---

## 5. Incident Response, Flow SIEM & Endpoint Threat Correlation

### Q5.1: High-priority alert indicates potential port scan or C2 beaconing from internal IP `192.0.2.77`. How to conduct incident triage?

- **Answer**:
  1. Open the Incidents module and locate the incident record for host `192.0.2.77` (`GET /api/incidents`, filter by status/time window).
  2. Open the incident detail: the app shows rule-based reasoning (fired rules, corroborating sources, evidence by role), confidence, timeline, and previous conclusions.
  3. Corroborate with flow data: query observability events/anomalies matching `192.0.2.77` (`GET /api/observability/anomalies`) and global triage status (`GET /api/triage-status`).
  4. Perform MAC location lookup on `192.0.2.77`'s MAC to identify the physical switch port.
  5. Generate the AI narrative for the incident via `POST /api/incidents/{incident_id}/explain` (rendered in the incident detail).

- **UI Navigation & Operational Workflow**:
  - **Tabs**: `Incidenti` (`navInvestigate` -> `#tab-incidents`, nav `#navIncidents`, admin-only, preview) & `AI Assistant` (`#tab-ai`).
  - **Incidents controls**: list container `#incidentsList` (not `#incidentsTableBody`); filters `#incStatusFilter` (status) and `#incWindowFilter` (time window); detail panel `#incidentDetail` with Ack/Resolve buttons (`setIncidentStatus(id, from, to)`), reasoning block, timeline, flow path, and AI block `#incidentAiBody` filled by `explainIncident(id)` -> `POST /api/incidents/{incident_id}/explain`. There are **no** `#btnRunIncidentTriage` or `#btnAiDiagnoseIncident` buttons.
  - **AI Assistant controls**: conversation list `#aiConvList`, thread `#aiChatMessages`, composer `#aiChatInput` + send button `#btnAiSend` (`sendAiChat()` -> `POST /api/ai/chat`), device attachment `#aiAttachDeviceBtn`/`#aiAttachTenant`.
- **Workflow Step-by-Step**:
    1. Click **Incidenti** under **Indaga**.
    2. Set `#incStatusFilter`/`#incWindowFilter` and locate the incident for `192.0.2.77` in `#incidentsList`.
    3. Open it to review rule reasoning, confidence, and evidence timeline.
    4. Cross-check top talkers/anomalies in the **Traffico** tab and run device triage from inventory (`POST /api/triage/{ip}`).
    5. Generate the AI narrative via the incident's AI action (`explainIncident`) or discuss the case in **AI Assistant** (`#aiChatInput` -> **Invia**).

- **App Features Present**:
  - **API Routes** ([routers/incidents.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/incidents.py), prefix `/api/incidents`): `GET /api/incidents` (L242), `GET /api/incidents/{incident_id}` (L283), `POST /api/incidents/{incident_id}/status` (L321), `POST /api/incidents/{incident_id}/explain` (L397), plus `/rules` (L42), `/rules/{rule_id}/parameters` (L52), `/interfaces` (L92), `/interfaces/expected` (L177)
  - **API Routes (triage)** ([routers/triage.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/triage.py)): `GET /api/triage-status` (L124) — not `/api/triage/status`; `POST /api/triage/{ip}` (L110); `POST /api/run-triage` (L79); `POST /api/ping-check` (L129)
  - **AI routes** ([routers/ai.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/ai.py)): `POST /api/ai/chat` (L509), profiles/conversations CRUD, `POST /api/ai/generate-config` (L676). There is **no** `/api/ai/diagnose` route.
  - **MCP Tools**: `get_triage_status`, `locate_mac`, `get_anomalies` (disabled by default) ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py))
  - **UI Modules**: `static/js/incidents.js`, `static/js/ai.js`

- **Missing Features / Gaps**:
  - **External Threat Intel API Integration**: No automatic AbuseIPDB / VirusTotal / AlienVault OTX reputation scoring of destination IPs in flow logs.
  - **SOAR Webhook Export**: No native webhook integration to push incident triage states to ServiceNow, Jira, Slack.

---

## 6. Security Compliance Audit, Rule Drift & Configuration Provisioning

### Q6.1: How to perform a security compliance audit on FortiGate or Cisco switch configurations?

- **Answer**:
  1. Run a **NetSec Audit** scan: the module evaluates a stored device backup (or pasted config text) against compliance benchmarks — **CIS** (FortiGate 7.4.x / Cisco IOS XE 17.x / Ubuntu 24.04 LTS), **NIST SP 800-53 Rev. 5**, and **PCI-DSS v4.0** — and returns violations with severity, remediation, and guidance.
  2. Use **Config Analyzer** for structural inspection of stored backups: firewall policies (including `logtraffic`), objects, VLANs, routing, ACLs, interfaces; FortiOS insecure management access (http/telnet in `allowaccess`) is flagged; IOS SNMP communities are parsed with ACL references.
  3. For maintenance-style audits, use **Checklist Audit Firewall**: template-driven engagements with per-item status, evidence uploads, and a final report.
  4. Download raw backups when needed (`GET /api/download-backup/{ip_or_filename}`).

- **UI Navigation & Operational Workflow**:
  - **Tabs**: `NetSec Audit` (`navAssess` -> `#tab-netsec-audit`, admin-only, preview), `Config Analyzer` (`#tab-config`), `Checklist Audit Firewall` (`navAuditChecklist` -> `#tab-audit-checklist`, admin-only).
  - **NetSec Audit controls**: benchmark selection + scan trigger in `static/js/netsec-audit.js` (endpoints `GET /api/netsec-audit/benchmarks`, `POST /api/netsec-audit/scan` with `device_ip` or `config_text`).
  - **Config Analyzer controls**: `#configGroupSelect` (tenant filter), `#caSearch`, `#caResults`, pills `#caPills`; analysis auto-loads — there is no `#configSelectBackup` / `#btnAnalyzeConfig` / `#inputFileConfig`.
  - **Audit Checklist controls**: engagements list `#auditEngagementList`; new audit via modal (`openNewAuditModal()`); template/engagement management in `static/js/audit_checklist.js`. There is no "Seleziona Modello Audit" select or "Esegui Audit Checklist" button — the workflow is engagement-based.
- **Workflow Step-by-Step**:
    1. Click **NetSec Audit** under **Valuta**, choose benchmark (cis / nist / pci), select a device with a stored backup (or paste config text), and run the scan.
    2. Review violations with severity, category, remediation text, and guidance.
    3. Open **Config Analyzer** for structural drill-down (policies, objects, routing, ACLs) and per-device backup refresh.
    4. For formal audits, open **Checklist Audit Firewall**, create an engagement from a template, fill items, attach evidence, and export the report.

- **App Features Present**:
  - **API Routes** ([routers/analyzer.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/analyzer.py)): `GET /api/netsec-audit/benchmarks` (L94), `POST /api/netsec-audit/scan` (L134) — there is no `/api/analyzer/config` route; `GET /api/config-analyzer` (L44), `GET /api/config-analyzer/{ip}` (L49), `POST /api/config-analyzer/convert` (L64)
  - **API Routes (audit checklist)** ([routers/audit_checklist.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/audit_checklist.py), prefix `/api/audit-checklist`): `GET /templates` (L50), template item CRUD (L56-L117), `GET/POST /engagements` (L119/L127), engagement items/evidence/report (L145-L208). There is no bare `GET /api/audit-checklist` route.
  - **API Route (backups)**: `GET /api/download-backup/{ip_or_filename}` ([routers/backup.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/backup.py#L30-L79)), `GET /api/search` (L81)
  - **MCP Tool**: `analyze_config` (calls `GET /api/config-analyzer/{ip}`) ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py))
  - **UI Modules**: `static/js/netsec-audit.js`, `static/js/config-analyzer.js`, `static/js/audit_checklist.js`
  - **Engine**: `services/netsec_audit/` (benchmarks, guidance, messages), `ai/config_analyzer.py` (FortiOS/IOS/WLC parsers), `fw_analyzers/` (vendor-driven envelopes)

- **Missing Features / Gaps**:
  - *(Removed from original: "PCI-DSS / CIS Benchmark Mapping Tagging" — this feature **exists**: NetSec Audit implements CIS, NIST SP 800-53 Rev. 5, and PCI-DSS v4.0 benchmarks with per-rule references.)*
  - **Automated Drift Alerting on Git Backup**: Backups are stored in-app; there is no auto-commit to Git with line-by-line diff notifications when configuration changes outside maintenance windows.
  - **Config File Upload for Ad-hoc Analysis**: NetSec Audit accepts pasted `config_text` via API, but Config Analyzer has no file-upload control in the UI.

---

## 7. Multi-Site VPN & Inter-VLAN Connectivity Troubleshooting

### Q7.1: Inter-site IPsec VPN tunnel between Main Site (`192.0.2.1`) and Branch Site (`198.51.100.1`) is down. How to troubleshoot IPsec phase 1/2 and routing?

- **Answer**:
  1. Query Sites list (`GET /api/sites`) and network map (`GET /api/network-map`) to review cross-site topology and gateway assignments.
  2. Fetch FortiGate interfaces and IPsec tunnel status for gateway `192.0.2.1` (`GET /api/fortigate/{ip}/interfaces`, `GET /api/fortigate/{ip}/vpn/tunnels`).
  3. Check the route table on `192.0.2.1` (`GET /api/fortigate/{ip}/routes`) to verify remote branch subnet `198.51.100.0/24` points to the IPsec virtual interface.
  4. Query FortiGate logs filtered to event type to identify IKE negotiation failures (pre-shared key mismatch, proposal mismatch).
  5. Run ping checks from the app (`POST /api/ping-check` / `GET /api/ping/{ip}`) to test reachability of the remote site.

- **UI Navigation & Operational Workflow**:
  - **Tabs**: `Sedi` (`navAdminister` -> `#tab-sites`) & `Fortigate Management` (`#tab-fortigate`).
  - **Controls**:
    - FortiGate pane **Rete** (`#fgtSub-network`) with pills: `Interfacce` (`#fgtPill-interfaces`), `VPN` (`#fgtPill-vpn` — tunnel status badges), `Routing` (`#fgtPill-routes`), plus ARP/DHCP/SD-WAN. There are no `#subtab-interfaces` / `#subtab-routes` controls.
    - FortiGate pane **Traffico** -> pill `Log` (`#fgtPill-logs`): set `#fgtLogType` = `event` to inspect IKE/VPN events.
- **Workflow Step-by-Step**:
    1. Click **Sedi** under **Amministra** to review multi-site gateway status.
    2. Click **Fortigate Management** and select main gateway `192.0.2.1`.
    3. Open pane **Rete**, pill **VPN**: check tunnel status badge (UP/DOWN) and byte counters.
    4. Pill **Routing**: verify static route for `198.51.100.0/24` points to the IPsec interface.
    5. Open pane **Traffico**, pill **Log**, set type `event`, and inspect IKE negotiation errors.

- **App Features Present**:
  - **API Route**: `GET /api/sites` ([routers/sites.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/sites.py#L51-L53))
  - **API Route**: `GET /api/network-map` ([routers/topology.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/topology.py#L60-L64)) — there is no `/api/topology/map` route; also `GET /api/topology` (L54), `GET /api/portchannels` (L82)
  - **API Routes**: `GET /api/fortigate/{ip}/interfaces` (L191), `GET /api/fortigate/{ip}/routes` (L287), `GET /api/fortigate/{ip}/vpn/tunnels` (L291), `GET /api/fortigate/{ip}/sdwan/health` (L297) ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py))
  - **MCP Tools**: `list_sites`, `get_network_map` (calls `/api/network-map`), `fortigate_interfaces`, `fortigate_routes` ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py))
  - **UI Modules**: `static/js/site-agent.js`, `static/js/fortigate-management.js`

- **Missing Features / Gaps**:
  - **IPsec IKE Debug Telemetry**: No streaming `diagnose debug application ike` via the app; troubleshooting relies on tunnel status, logs, and manual CLI.
  - **BGP / OSPF Neighbor State Telemetry**: No dedicated parser/API for dynamic routing neighbor adjacency status (BGP ESTABLISHED / OSPF FULL).

---

## 8. Infrastructure Health & Monitoring Triage

### Q8.1: The Linux server hosting SentinelNet collectors reports degradation. How to assess health state?

- **Answer**:
  1. Check the observability pipeline itself: `GET /api/observability/health` returns enabled state, active listeners, metrics counters, DB size, and schema version.
  2. For polled device/host snapshots (REST observations, including Linux host metrics when `linux_poll_s` is enabled), query `GET /api/observability/api-context?device_ip=<host>` — this is the endpoint behind the MCP `linux_health` tool. There is **no** `/api/observability/linux-health` route.
  3. Verify listener configuration in Settings -> Observability (bind address, API/SNMP/Linux polling intervals).
  4. If the observability DB grows due to accumulated logs, prune via `POST /api/observability/prune-logs` (API-only — no UI button).

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Impostazioni` (`navAdminister` -> `#tab-settings`).
  - **Controls**: Observability settings render into `#obsSettingsBody` (`static/js/observability.js`): enable checkbox `#obs_enabled`, bind address `#obs_bind`, polling intervals `#obs_api_poll_s` / `#obs_snmp_poll_s` / `#obs_linux_poll_s`, restart banner `#obsRestartBanner`. There are **no** `#tab-obs-settings`, `#subtab-health`, or `#btnPruneLogs` controls, and no CPU/RAM/Disk KPI cards or service badges in Settings.
- **Workflow Step-by-Step**:
    1. Click **Impostazioni** under **Amministra** and open the Observability settings section.
    2. Verify observability is enabled and listeners are bound (banner warns when no listener is active; check `GET /api/observability/health`).
    3. Review polling intervals; trigger a one-shot API poll with `POST /api/observability/api-poll` if needed.
    4. To reclaim space, call `POST /api/observability/prune-logs` with `{"days": N}` (deletes `syslog_events` and `flow_aggregates` older than N days).

- **App Features Present**:
  - **API Route**: `GET /api/observability/health` ([routers/observability.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/observability.py#L671-L688)) — not `/api/observability/status`
  - **API Route**: `GET /api/observability/api-context` ([routers/observability.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/observability.py#L642-L658)); `POST /api/observability/api-poll` (L661)
  - **API Route**: `POST /api/observability/prune-logs` ([routers/observability.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/observability.py#L699-L705)) — **API-only, no UI button**
  - **MCP Tool**: `linux_health` (calls `/api/observability/api-context`; **disabled by default**) ([ai/mcp_server.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/ai/mcp_server.py))
  - **UI Module**: `static/js/observability.js` (settings renderer + flows/anomalies views)

- **Missing Features / Gaps**:
  - **Health/Prune UI**: No System Health panel, service badges, or Purge Logs button in the dashboard; all diagnostics are API-level.
  - **Automated Threshold Trigger**: No background auto-purge on high disk/DB watermark; pruning requires an explicit operator/API call.

---

## Summary Matrix of Capabilities vs Gaps (corrected)

| Domain | Present App Features | Key Missing Features / Gaps |
| :--- | :--- | :--- |
| **FortiGate Firewalls** | Policy lookup, live sessions, session kill **API** (no UI button), traffic/event logs, policies **with hit counts & last-used**, interfaces/ARP/DHCP/routes/VPN tunnels/SD-WAN health, managed FortiAP (`/wifi/aps`, `/wifi/clients`), day-0 config generation + push (SSH/serial/REST), REST driver with SSH fallback | Raw packet capture (`sniffer`), deep UTM sub-log parsing, session-kill & CLI-console UI buttons |
| **Cisco WLC (AireOS/9800)** | WLC tab: status, AP summary, client summary/detail, WLAN summary, rogue APs, client diagnostics + modal | 802.11 roaming history timeline, RF floorplan heatmaps, active rogue containment |
| **MAC & IP Tracing** | MAC search/locate across switches, client map (via `/api/arp/*`), ARP collection, endpoint inventory, port-control **API** | 802.1X/RADIUS correlation, **port-isolation UI button** |
| **Flow SIEM & Anomalies** | Top talkers & anomalies via `/api/observability/*`, Flow SIEM events/histogram/facets, IP shun **API** (`/api/flow-siem/shun-ip`) | Shun IP UI button, BGP Flowspec/ACL auto-injection, JA3/SNI inspection, external Threat Intel scoring |
| **Config & Compliance** | Config Analyzer (structural), **NetSec Audit (CIS / NIST SP 800-53 / PCI-DSS v4.0 benchmarks)**, audit checklist engagements, config backup storage/download, FortiOS<->PAN-OS converter | Policy-object level provisioning form, transactional push with rollback validation, Git drift alerts, ad-hoc config file upload UI |
| **Incidents & AI** | Rule-based incident engine (reasoning/timeline/status), AI narrative per incident (`/explain`), AI Assistant chat, triage endpoints | External threat intel enrichment, SOAR webhook export |
| **Observability/Health** | Pipeline health endpoint, per-device REST snapshots (`api-context`), log pruning **API** | Linux health UI panel, auto-purge on watermark, service status badges |
