# Network Security Operational Triage & Troubleshooting Q&A Guide — v3

> **Status**: supersedes `netsec_troubleshooting_qa.md` (original, many wrong routes/IDs) and
> `netsec_troubleshooting_qa_corrected.md` (correct on 2026-08-08, now partly stale).
> Verified on **2026-08-11** against `HEAD = e14c0c1`, checking `routers/*.py`,
> `ai/mcp_server.py`, `routers/mcp.py`, `templates/dashboard.html` and `static/js/*.js`.
> Line numbers are those of that commit and drift with any edit — treat them as hints, not contracts.

## What changed since the 2026-08-08 corrected version

| Area | Change |
| :--- | :--- |
| **Cisco WLC** | Tab now loads through a single consolidated route `GET /api/wlc/{ip}/overview` (one SSH session: AP + client + WLAN + rogue). Controller selection is **tenant-first** (`#wlcTenantSelect` → `#wlcTargetSelect`). AP table gained a 5 GHz channel/width column from `show ap auto-rf 802.11a`; client table gained a quality column and a live search box. The per-object routes (`/status`, `/ap-summary`, …) still exist for API/MCP consumers; the UI no longer calls them one by one. Route line numbers shifted (status is now L50, not L39). |
| **FortiGate** | New aggregated client diagnosis: `POST /api/fortigate/{ip}/diagnose-client` + pill **Diagnosi Client** (`#fgtPill-clientDiagnosis`) + MCP `fortigate_diagnose_client`. |
| **Client Diagnosis (new §9)** | The `#tab-diagnosi` tab and `routers/diagnosis.py` (`/api/diagnose/client`, `/gateway-candidates`, `/traceroute-gateway`, `/port-bounce`) were not covered at all by either previous document. **`/api/diagnose/port-bounce` does have a UI button** — so "no port action has a UI" is no longer true in general (`/api/mac/port-control` still has none). |
| **NetSec Audit** | Config **file upload / drag-and-drop now exists** in the UI (`#auditDropZone`, `#auditFileInput` → `config_text`), plus PDF export (`#btnPdfNetsec`), benchmark select, severity/category filters and a score/grade badge. The corrected doc's gap "no ad-hoc config file upload UI" is **withdrawn**. |
| **Subnet scan** | Scan is now **discovery-only**; credential verification is a separate opt-in step `POST /api/scan-verify` using stored identities. Relevant to unknown-host workflows (§2.2). |
| **Line numbers** | Many shifted, notably `POST /api/send-command` (now `routers/commands.py:159`) and the `netsec-audit` routes (`analyzer.py:97` / `:137`). |

## Still true from the corrected version (do not regress)

- MCP tools live in `ai/mcp_server.py` (`TOOLS` dict), **not** `routers/mcp.py` — that router only serves
  `/api/mcp/settings` and `/api/mcp/tool-config`.
- `get_top_talkers`, `get_anomalies`, `linux_health` are **disabled by default**
  (`routers/mcp.py:15`, `_MCP_DEFAULT_DISABLED`) until an admin enables them.
- The FortiGate tab is built from panes `#fgtPane-*` (switched by the `#fgtSub-*` button bar) and view
  pills `#fgtPill-*` rendering into `#fgtView-*`. There is no `#subtab-*` family anywhere.
  *(Both earlier documents, and the first draft of this one, called `#fgtSub-*` the panes — those are
  the bar buttons; the containers are `#fgtPane-*`.)*
- Routes that exist **API-only, with no UI button**: `POST /api/flow-siem/shun-ip` (deferred by the
  owner, see `docs/Improvements`) and `POST /api/mac/port-control`.
  `DELETE /api/fortigate/{ip}/sessions` and `POST /api/observability/prune-logs` **got their buttons on
  2026-08-11** — session kill sits next to the Sessioni form (`#btnFgtSessionKill`, refuses an empty
  filter set, which would have killed every session), the purge sits in Settings -> Observability.
- These routes named by the original document **do not exist**: `/api/fortigate/{ip}/managed-aps`,
  `/api/mac/mac-to-ip`, `/api/mac/client-map`, `/api/endpoint-inventory`, `/api/flow-siem/top-talkers`,
  `/api/flow-siem/anomalies`, `/api/analyzer/config`, `/api/triage/status`, `/api/ai/diagnose`,
  `/api/observability/linux-health`, `/api/observability/status`, `/api/topology/map`,
  `/api/provisioner/generate-fortigate-config`.

---

## Overview & System Context

SentinelNet provides network security observability, triage, client diagnosis and configuration
auditing across multi-vendor infrastructure: Fortinet FortiGate firewalls, Cisco Wireless LAN
Controllers (AireOS and Catalyst 9800), campus switches (Cisco, Aruba, HP) and Linux hosts.

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

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Fortigate Management` (`#navFortigate` → `#tab-fortigate`) under **Inventario**, admin-only.
  - **Structure**: a subtab bar of buttons `#fgtSub-overview` / `-network` / `-firewall` / `-traffic` /
    `-security` / `-wifi` / `-settings` (`fgtSwitchView('<pane>')`) toggles the pane containers
    `#fgtPane-overview` … `#fgtPane-settings`. Each pane holds view pills `#fgtPill-*`
    (`fgtPickView('<pane>','<view>')`) rendering into `#fgtView-*`, plus a shared `Aggiorna`
    (`refreshFgtView()`). Target selector `#fgtTargetSelect`. 7 panes, 25 pills.
  - **Policy Lookup**: pane **Firewall** → pill `Verifica Policy` (`#fgtPill-policyLookup`) → form
    `#fgtForm-policyLookup`: `#fgtLookupSrc`, `#fgtLookupDst`, `#fgtLookupProto` (TCP/UDP/ICMP),
    `#fgtLookupPort`, `#fgtLookupIntf` → run button (no ID, `onclick="loadFgtDataset('policyLookup')"`,
    i18n `btnFgtLookupRun`).
  - **Sessions**: pane **Traffico** → pill `Sessioni` (`#fgtPill-sessions`) → `#fgtSessSrc`,
    `#fgtSessDst`, `#fgtSessPort` → `onclick="loadFgtDataset('sessions')"`.
  - **Logs**: pane **Traffico** → pill `Log` (`#fgtPill-logs`) → `#fgtLogDevice` (disk/memory),
    `#fgtLogType` (traffic/event/utm), `#fgtLogSubtype` (forward/local/virus/webfilter/ips),
    `#fgtLogSrc`, `#fgtLogDst`, `#fgtLogAction`, `#fgtLogSince`/`#fgtLogUntil`, `#fgtLogCount`.
  - **Client diagnosis (new)**: pane **Traffico** → pill `Diagnosi Client` (`#fgtPill-clientDiagnosis`,
    `fgtPickView('traffic','clientDiagnosis')`) → aggregated device-inventory + ARP + DHCP + sessions +
    policy match + recent logs for one client. The same pane also holds `Inventario Dispositivi`
    (`#fgtPill-deviceInventory` — FortiGate-discovered devices, unrelated to the Network Inventory tab).
- **Workflow Step-by-Step**:
    1. Open **Fortigate Management** under **Inventario**; pick `192.0.2.1` in `#fgtTargetSelect`.
    2. Pane **Firewall** → pill **Verifica Policy**; fill `192.0.2.105` / `198.51.100.45` / `443`, run.
    3. Pane **Traffico** → pill **Sessioni**; `#fgtSessSrc = 192.0.2.105`, load.
    4. Pill **Log**: `disk` + `traffic` + `forward`, load, inspect denied rows.
    5. Or skip 2–4: pill **Diagnosi Client**, enter the client and the destination.

- **App Features Present**:
  - `POST /api/fortigate/{ip}/policy-lookup` ([routers/fortigate.py:264](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L264))
  - `POST /api/fortigate/{ip}/sessions` ([routers/fortigate.py:272](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L272))
  - `DELETE /api/fortigate/{ip}/sessions` ([routers/fortigate.py:279](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L279)) — **API-only, no UI button**
  - `POST /api/fortigate/{ip}/logs` ([routers/fortigate.py:302](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L302))
  - `POST /api/fortigate/{ip}/diagnose-client` ([routers/fortigate.py:327](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L327)) — **new since 2026-08-08**
  - `GET /api/fortigate/{ip}/firewall/policies-with-stats` ([routers/fortigate.py:226](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L226)) — hit counts, active sessions, last used
  - **MCP**: `fortigate_policy_lookup`, `fortigate_sessions`, `fortigate_traffic_logs`,
    `fortigate_policies`, `fortigate_policy_stats`, `fortigate_diagnose_client`, `fortigate_full_config`
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
  4. Deliver via `.txt` download, SSH push, serial/console push, or FortiGate REST push (SSH fallback).

- **UI Navigation & Operational Workflow**:
  - **Tabs**: `Config Analyzer` (`navAssess` → `#tab-config`), and — under the single nav item
    "Provisioning" (`navChange`, requires-write) — **two distinct surfaces**: `#tab-provisioning`
    ("Provisioning Apparato" = device onboarding CRUD, tenant/transport/credential fields) and
    **`#tab-provisioner`** ("Apparato da Zero" = day-0 config generation). Everything below lives in
    `#tab-provisioner`, not `#tab-provisioning`.
  - **Config Analyzer**: tenant filter `#configGroupSelect`, search `#caSearch`, pills `#caPills`
    (Home / Firewall / Server / VLAN / Routing / ACL / Interfacce / Converti), results `#caResults`.
    The analysis auto-loads from `GET /api/config-analyzer?group=<group>`; there is **no**
    `#configSelectBackup`, **no** `#btnAnalyzeConfig` and **no** upload control in this tab
    (upload lives in NetSec Audit, see §6).
  - **Provisioning (`#tab-provisioner`)**: FortiGate day-0 fields (`#fgtMgmtIf`, `#fgtMgmtIp`,
    `#fgtWanIf`, `#fgtWanMode`, `#fgtLanIf`, DNS/NTP/Syslog/SNMPv3/AAA, hardening checkboxes) or Cisco
    switch fields (`#provHostname`, `#provRole`, VLAN/port fields) → `#btnProvGenerate`,
    `#btnProvDownload`, delivery mode `#provDeliveryMode`.

- **App Features Present**:
  - `GET /api/config-analyzer` ([routers/analyzer.py:44](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/analyzer.py#L44)),
    `GET /api/config-analyzer/{ip}` (L49), `POST /api/config-analyzer/convert` (L67, FortiOS ↔ PAN-OS)
  - `POST /api/provisioner/fgt/generate` (L221), `/fgt/download` (L230), `/fgt/push-ssh` (L245 — REST
    first when a token is stored, SSH fallback), `/fgt/push-serial` (L281); Cisco equivalents
    `/api/provisioner/generate` (L152), `/download` (L162), `/push-ssh` (L177), `/push-serial` (L199),
    `GET /api/provisioner/serial-ports` (L216)
    ([routers/provisioner.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/provisioner.py)).
    Push routes are admin-gated.
  - Identity store for push credentials: `GET/POST /api/identities` (L309/L314),
    `PUT/DELETE /api/identities/{id}` (L324/L336), `POST /api/identities/{id}/assign` (L353)
  - **MCP**: `generate_fortigate_config`, `generate_switch_config`, `analyze_config`
  - **UI**: `static/js/config-analyzer.js`, `static/js/provisioning.js`

- **Missing Features / Gaps**:
  - **Policy-Object Provisioning Form**: no UI/API generating a single policy block from
    (src, dst, services, interfaces, action).
  - **Transactional Push With Rollback**: push exists (SSH/serial/REST) but no commit verification or
    auto-rollback on failure/connectivity loss.
  - **Shadow Policy Detector**: nothing checks whether a higher-priority rule already permits or denies
    the pattern before a new policy is suggested.

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
     access port; `POST /api/mac/port-control` performs an administrative shutdown and remains
     **API/MCP-only**.

- **UI Navigation & Operational Workflow**:
  - **Tab group** `Localizzazione Endpoint` (`navInvestigate`), subtabs `#tab-mac` (MAC Tracker),
    `#tab-clientmap` (Client Map), `#tab-diagnosi` (Diagnosi Client), `#tab-endpoints` (Inventario
    Endpoint) — the four share one subtab bar.
  - **MAC Tracker**: `#macSearchMac` (partial/OUI ok), `#macSearchVlan`, `#macSearchIface`,
    `#macSearchSwitch`; search button (no ID, `onclick="macSearch()"`, i18n `btnMacSearchGo`); reset
    `macSearchReset()`; results `#macResults`; stats chip `#macStats`.
  - **Client Map**: MAC↔IP bindings from gateway ARP tables cross-referenced with tracker ports.

- **App Features Present**:
  - `GET /api/mac/search` ([routers/mac.py:139](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mac.py#L139)),
    `GET /api/mac/locate` (L158), `GET /api/mac/switch/{ip}` (L190), `GET /api/mac/stats` (L195)
  - `POST /api/mac/scan` (L105) — on-demand MAC-table collection
  - `POST /api/mac/port-control` (L241) — **API/MCP-only**
  - MAC→IP / Client Map: `GET /api/arp/search` ([routers/arp.py:53](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/arp.py#L53)),
    `GET /api/arp/client-map` (L62), `GET /api/arp/stats` (L85)
  - **MCP**: `locate_mac`, `search_mac`, `mac_to_ip` (→ `/api/arp/search`), `client_map`
    (→ `/api/arp/client-map`)
  - **UI**: `static/js/client-map.js`

- **Missing Features / Gaps**:
  - **802.1X / RADIUS Telemetry**: no RADIUS auth history (username, EAP method, posture) per MAC from
    Cisco ISE or FreeRADIUS.
  - **Port Shutdown UI**: `/api/mac/port-control` still has no button (the Diagnosi tab exposes only
    the bounce, which is shut + no-shut, not a lasting isolation).

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
  - The ARP collection panel lives in **Client Map** (`#tab-clientmap`), **not** in `#tab-mac`.
  - Controls: tenant `#arpScanGroup`, gateway multi-select `#arpDeviceMenu`, `#btnArpScan`
    (`runArpScan()`), filters `#arpSearchMac` / `#arpSearchIp` (`arpClientSearch()`), KPIs
    `#kpiArpBindings`, `#kpiArpUniqueMacs`, `#kpiArpGateways`.
  - **Inventario Endpoint** (`#tab-endpoints`): mode buttons `#epModeListBtn` / `#epModePortsBtn`,
    switch select `#epPortsSwitch`, filters `#epFilterQ`, `#epFilterTenant`, `#epFilterStale`,
    exports `endpointsExport('csv'|'json')`, KPIs `#epKpis`, results `#epResults`.

- **App Features Present**:
  - `POST /api/arp/scan` ([routers/arp.py:21](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/arp.py#L21))
  - `GET /api/endpoints/list` ([routers/endpoint_inventory.py:35](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/endpoint_inventory.py#L35)),
    `GET /api/endpoints/ports` (L52) — there is no `/api/endpoint-inventory`
  - `POST /api/scan-subnet` ([routers/scan.py:54](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/scan.py#L54)),
    `POST /api/scan-verify` (L141, **new**), `GET /api/scan-subnet/{job_id}` (L181)
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
  5. Check the AP row for client density and the 5 GHz channel/width reported by
     `show ap auto-rf 802.11a` (AireOS) to spot co-channel or width mismatches.

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Cisco WLC` (`#navWlc` → `#tab-wlc`).
  - **Controls**: tenant select `#wlcTenantSelect` (`onWlcTenantChanged()`), controller select
    `#wlcTargetSelect` (disabled until a tenant is picked, `onWlcTargetChanged()`), `Aggiorna`
    (`refreshWlcData()`), status panel `#wlcStatusBox`.
  - **Tables**: AP `#wlcApTableBody` (name, IP, ethernet MAC, state, clients, **5 GHz channel/width**,
    model), clients `#wlcClientTableBody` (MAC, IP, AP, WLAN/SSID, RSSI/SNR, **quality**, actions) with
    counter `#wlcClientCount` and live filter `#wlcClientSearch` (`onWlcClientSearch()`), WLANs
    `#wlcWlanTableBody`, rogues `#wlcRogueTableBody`.
  - **Diagnostics**: row action `wlcDiagnoseClient(mac)` → modal `#wlcDiagModal` / `#wlcDiagModalBody`.

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
  - `GET /api/fortigate/{ip}/wifi/aps` ([routers/fortigate.py:317](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L317)),
    `GET /api/fortigate/{ip}/wifi/clients` (L313) — there is no `/managed-aps` route
  - **MCP**: `wlc_rogue_aps`, `fortigate_managed_aps` (→ `/wifi/aps`), `fortigate_wifi_clients`

- **Missing Features / Gaps**:
  - **Active Rogue Containment**: no deauth / wireless containment trigger from the app.
  - **Wired Rogue Auto-Block**: no automatic port disable for a rogue MAC seen on a switch (manual path:
    MAC Tracker → Diagnosi → port bounce, or `POST /api/mac/port-control` via API).

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
    `GET /api/observability/events` (L295), `GET /api/observability/flowgraph` (L448)
  - `GET /api/observability/anomalies` (L340), `POST /api/observability/anomalies/{event_id}/status`
    (L385) — the latter is **deprecated** and delegates to `POST /api/incidents/{id}/status`;
    the Traffico tab calls the incidents route directly
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
  5. Drain: `DELETE /api/fortigate/{ip}/sessions` (API/MCP only) or `diagnose sys session clear` via
     `POST /api/send-command` / MCP `send_cli_command`. There is no CLI console button in this tab.

- **UI Navigation & Operational Workflow**:
  - Pane **Panoramica** (`#fgtSub-overview`): status tiles + `#fgtView-resources` + `#fgtView-ha`.
  - Pane **Traffico** → pill **Sessioni**: `#fgtSessSrc`, `#fgtSessDst`, `#fgtSessPort`.
  - Pane **Firewall** → pill **Policy** (`#fgtPill-policies`): hit counts / active sessions / last used.
  - There is **no** `#btnFgtSessionKill` and **no** `#btnOpenCli`.

- **App Features Present**:
  - `GET /api/fortigate/{ip}/status` (L155), `/system/resources` (L159), `/system/ha` (L164)
  - `POST` / `DELETE /api/fortigate/{ip}/sessions` (L272 / L279)
  - `GET /api/fortigate/{ip}/policy-stats` (L212), `/firewall/policies-with-stats` (L226)
  - `POST /api/send-command` ([routers/commands.py:159](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/commands.py#L159)),
    `POST /api/bulk-command` (L208), `GET /api/bulk-command/{job_id}` (L265), `POST /api/ws-token` (L284)
  - **MCP**: `fortigate_status`, `fortigate_sessions`, `fortigate_policy_stats`, `send_cli_command`

- **Missing Features / Gaps**:
  - **CLI Console UI**: no embedded console in the tab (session kill got its button on 2026-08-11).
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
    **not** `/api/triage/status`, `POST /api/ping-check` (L130), `GET /api/ping/{ip}` (L179)
  - AI ([routers/ai.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/ai.py)):
    `POST /api/ai/chat` (L509), `POST /api/ai/generate-config` (L676), profiles/conversations CRUD.
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
  3. Use **Checklist Audit Firewall** for engagement-style audits: templates, per-item status, evidence
     upload, final report.
  4. Download raw backups when needed.

- **UI Navigation & Operational Workflow**:
  - **Tabs**: `NetSec Audit` (`#navNetSecAudit` → `#tab-netsec-audit`, admin-only, preview),
    `Config Analyzer` (`#tab-config`), `Checklist Audit Firewall` (`#navAuditChecklist` →
    `#tab-audit-checklist`, admin-only).
  - **NetSec Audit controls** (rendered by `static/js/netsec-audit.js` into the empty `#tab-netsec-audit`):
    benchmark `#auditBenchmarkSelect`, device `#auditDeviceSelect`, **config upload / drag-and-drop
    `#auditDropZone` + `#auditFileInput` + `#auditDropText`** (sent as `config_text`), run
    `#btnRunAuditScan`, score `#auditScoreValue` + `#auditGradeBadge`, filters `#auditSevFilter` /
    `#auditCatFilter`, results `#auditRulesTableBody`, requirements view `#auditBenchmarkReqs` /
    `#auditBenchmarkReqsBody`, partial-coverage warning `#auditPartialWarning`, report language
    `#auditReportLang`, PDF export `#btnPdfNetsec`.
  - **Config Analyzer**: `#configGroupSelect`, `#caSearch`, `#caPills`, `#caResults` — auto-loads,
    no upload, no analyze button.
  - **Audit Checklist**: engagements `#auditEngagementList`, new audit modal `openNewAuditModal()`.
    There is no "Seleziona Modello Audit" select and no "Esegui Audit Checklist" button.

- **App Features Present**:
  - `GET /api/netsec-audit/benchmarks` ([routers/analyzer.py:97](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/analyzer.py#L97)),
    `POST /api/netsec-audit/scan` (L137, accepts `device_ip` **or** `config_text`)
  - `GET /api/config-analyzer` (L44), `/{ip}` (L49), `POST /api/config-analyzer/convert` (L67)
  - Audit checklist (prefix `/api/audit-checklist`,
    [routers/audit_checklist.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/audit_checklist.py)):
    `GET /templates` (L50), `GET /templates/{id}` (L56), item CRUD (L80/L93/L106),
    `GET /engagements` (L119), `POST /engagements` (L127), `GET /engagements/{id}` (L145),
    `PATCH /engagements/{id}` (L154), `PUT /engagements/{id}/items/{ref}` (L172),
    `POST /engagements/{id}/evidence` (L191), `GET /engagements/{id}/report` (L208)
  - `GET /api/download-backup/{ip_or_filename}` ([routers/backup.py:30](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/backup.py#L30)),
    `GET /api/search` (L81)
  - **MCP**: `analyze_config`
  - **Engine**: `services/netsec_audit/`, `ai/config_analyzer.py`, `fw_analyzers/`

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
  - `GET /api/sites` ([routers/sites.py:51](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/sites.py#L51)),
    site CRUD + token regeneration (L55–L83), `POST /api/sites/{site_id}/command` (L91),
    `GET /api/command-jobs/{job_id}` (L122), agent update/restart/config/inventory/flow-control
    (L152–L235)
  - `GET /api/topology` ([routers/topology.py:55](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/topology.py#L55)),
    `GET /api/network-map` (L61) — **not** `/api/topology/map`, `POST /api/map/export/vsdx` (L67),
    `GET /api/portchannels` (L83)
  - `GET /api/fortigate/{ip}/interfaces` (L191), `/routes` (L287), `/vpn/tunnels` (L291),
    `/sdwan/health` (L297)
  - **MCP**: `list_sites`, `get_network_map`, `get_port_channels`, `fortigate_interfaces`,
    `fortigate_routes`, `fortigate_arp`, `fortigate_dhcp_leases`, `fortigate_device_inventory`
  - **UI**: `static/js/site-agent.js`, `static/js/fortigate-management.js`

- **Missing Features / Gaps**:
  - **IPsec IKE Debug Streaming**: no `diagnose debug application ike` stream; only tunnel state, logs
    and manual CLI.
  - **BGP / OSPF Neighbor Telemetry**: no parser/API for dynamic routing adjacency state.

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
     and `flow_aggregates` older than N days). **API-only, no button.**

- **UI Navigation & Operational Workflow**:
  - **Tab**: `Impostazioni` (`navAdminister` → `#tab-settings`); observability settings render into
    `#obsSettingsBody` by `static/js/observability.js`: `#obs_enabled`, `#obs_bind`, `#obs_api_poll_s`,
    `#obs_snmp_poll_s`, `#obs_linux_poll_s`, restart banner `#obsRestartBanner`.
  - There are **no** `#tab-obs-settings`, `#subtab-health`, `#btnPruneLogs`, no CPU/RAM/disk KPI cards
    and no service badges anywhere in the dashboard.

- **App Features Present**:
  - `GET /api/observability/health` ([routers/observability.py:671](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/observability.py#L671))
  - `GET /api/observability/api-context` (L642), `POST /api/observability/api-poll` (L661)
  - `GET/POST /api/observability/config` (L597/L604)
  - `POST /api/observability/prune-logs` (L699) — one-off purge, wired to the Settings panel since
    2026-08-11; the scheduled per-table retention is `observability/rollup.py:71` `retention_loop()`
  - `GET /api/ping-monitor/status` ([routers/settings.py:177](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/settings.py#L177))
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
  - **Tab**: `Diagnosi Client` (`#tab-diagnosi`, under **Localizzazione Endpoint**).
  - **Controls**: `#diagClientInput` (IP or MAC), `#diagDestInput`, gateway `#diagGatewaySelect` +
    `#diagGatewayInput` + `Traceroute` (`detectGatewayTracerouteUI()`), `#diagProtoInput`,
    `#diagPortInput`, run (`runDiagnosi()`), report `#diagResult`, and the port action
    `diagBouncePort()` inside the report.

- **App Features Present**:
  - `POST /api/diagnose/client` ([routers/diagnosis.py:48](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/diagnosis.py#L48)) — read-only, `get_current_user`
  - `GET /api/diagnose/gateway-candidates` (L74)
  - `POST /api/diagnose/traceroute-gateway` (L88) — scope enforced in the service, not by
    `assert_device_allowed`, because the target is not an inventory device
  - `POST /api/diagnose/port-bounce` (L103) — **admin-only, the only write in this tab**, and the only
    port action with a UI button
  - `POST /api/fortigate/{ip}/diagnose-client` ([routers/fortigate.py:327](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L327)) — the firewall-side equivalent
  - **MCP**: `diagnose_client` (cross-site, accepts an optional `tenant`), `fortigate_diagnose_client`
  - **Service**: `services/client_diagnosis.py`; **UI**: `static/js/diagnosi.js`

- **Missing Features / Gaps**:
  - **Historical Replay**: the report is a point-in-time snapshot; there is no "how did this client look
    an hour ago" view.
  - **Wireless Leg**: a wireless client is diagnosed from the wired/gateway side; the WLC client
    diagnostic (§3.1) is a separate tab and is not merged into this report.
  - **Persistent Isolation**: bounce only; a lasting quarantine still needs `/api/mac/port-control`
    via API/MCP.

---

## Summary Matrix of Capabilities vs Gaps (v3)

| Domain | Present App Features | Key Missing Features / Gaps |
| :--- | :--- | :--- |
| **FortiGate** | Policy lookup, sessions (+kill API), traffic/event/UTM logs, policies with hit counts & last-used, interfaces/ARP/DHCP/routes/VPN/SD-WAN, managed FortiAP, **aggregated client diagnosis**, full-config fetch, day-0 generation + push (SSH/serial/REST), REST driver with SSH fallback | Packet capture (`sniffer`), deep UTM sub-log parsing, session-kill & CLI-console UI buttons |
| **Cisco WLC** | **Tenant-scoped controller selection**, single-call `overview` (AP/clients/WLAN/rogue), **2.4 & 5 GHz auto-RF channel, width and utilization**, client quality + live search, rogue table, per-client diagnostics modal | Roaming (802.11r/k/v) timeline, RF floor-plan heatmap, 6 GHz auto-RF (needs the IOS-XE path), active rogue containment |
| **MAC / ARP / Endpoints** | MAC search & locate, on-demand MAC scan, ARP collection from L3 gateways, client map, endpoint inventory with exports, **discovery-only subnet scan + opt-in credential verification** | 802.1X/RADIUS correlation, DHCP-snooping cross-check, OS fingerprinting, port-shutdown UI |
| **Client Diagnosis** | **L2+L3 single-client report, gateway auto/traceroute detection, tenant-scoped, admin port bounce with staleness guard** | Historical replay, merged wireless leg, persistent quarantine |
| **Flow SIEM & Anomalies** | Top talkers, protocol distribution, flow graph, syslog/events, anomaly triage with status, Flow SIEM events/histogram/facets/suppression, shun API | Shun UI button, ACL/Flowspec auto-injection, JA3/SNI inspection, external threat intel |
| **Config & Compliance** | Config Analyzer (structural, FortiOS↔PAN-OS converter), **NetSec Audit with CIS/NIST 800-53/PCI-DSS v4.0, config upload & PDF report**, checklist engagements with evidence, backup storage/download | Git drift alerting, scheduled/recurring audits with score trend, policy-object provisioning form, transactional push with rollback |
| **Incidents & AI** | Rule-based incident engine (reasoning, evidence, timeline, status), AI narrative per incident, AI Assistant chat with device/tenant attachments, triage & ping endpoints | External threat-intel enrichment, SOAR webhook export |
| **Observability / Health** | Pipeline health, per-device REST snapshots, listener configuration, prune API, ping monitor status | Health UI panel, auto-purge watermark, service badges |
| **MCP surface** | 43 tools in `ai/mcp_server.py`, per-tool enable/disable via `/api/mcp/settings` | `get_top_talkers`, `get_anomalies`, `linux_health` disabled until an admin enables them |
