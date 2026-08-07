# Network Security Operational Triage & Troubleshooting Q&A Guide

## Overview & System Context

SentinelNet provides network security observability, triage, and configuration auditing across multi-vendor infrastructure including Fortinet FortiGate firewalls, Cisco Wireless LAN Controllers (AireOS and Catalyst 9800), campus switches (Cisco, Aruba, HP), and Linux server infrastructure.

This document formulates operational troubleshooting scenarios, step-by-step resolution workflows, existing SentinelNet features, and identified capability gaps for Network Security Engineers.

---

## 1. Firewall Policy Triage & Traffic Inspection

### Q1.1: User reports outbound web traffic to destination `198.51.100.45:443` is being dropped by core firewall `192.0.2.1`. How to diagnose policy evaluation and rule match?

- **Answer**:
  1. Perform dry-run policy lookup on target FortiGate via API using source IP `192.0.2.105`, destination `198.51.100.45`, protocol `TCP`, and destination port `443`.
  2. Inspect returned matched policy ID, action (`accept` / `deny`), source/destination interfaces, and active UTM/IPS profile attachments.
  3. Query FortiGate active session table filtered by source IP `192.0.2.105` and destination IP `198.51.100.45` to verify if session state is established, in SYN-SENT state, or subject to TCP reset/timeout.
  4. Query FortiGate traffic log stream for recent log entries matching target source/destination pair to check log action, drop reason code, and security event tags (e.g., AV block, Web Filter category drop, IPS trigger).
  5. Validate static routing path on FortiGate for `198.51.100.45` to verify egress interface matches expected policy source/destination interface pair.

- **App Features Present**:
  - **API Route**: `POST /api/fortigate/{ip}/policy-lookup` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L47-L52))
  - **API Route**: `POST /api/fortigate/{ip}/sessions/query` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L54-L59))
  - **API Route**: `POST /api/fortigate/{ip}/traffic-logs/query` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L60-L65))
  - **MCP Tools**: `fortigate_policy_lookup`, `fortigate_sessions`, `fortigate_traffic_logs`, `fortigate_policies` ([routers/mcp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mcp.py))
  - **UI Module**: FortiGate Live Inspector tab (`static/js/fortigate.js`)

- **Missing Features / Gaps**:
  - **Live Packet Capture**: Lacks real-time CLI sniffer API integration (`diagnose sniffer packet`) to capture raw PCAP payload bytes directly from browser.
  - **UTM Detailed Event Breakdown**: Log summary returns generic traffic log actions; does not parse deep UTM sub-logs (Application Control, Antivirus, SSL Inspection failure reasons) into dedicated structured UI cards.
  - **Policy Hit Count Telemetry**: Does not fetch cumulative FortiGate rule hit counts or last-used timestamps to identify unused or shadowed rules dynamically during lookup.

---

### Q1.2: A firewall rule update was requested for host `192.0.2.50` requiring access to SSH (`22`) and HTTPS (`443`) on `198.51.100.20`. How to verify and generate compliant FortiOS policy syntax?

- **Answer**:
  1. Execute configuration analyzer against target FortiGate backup to check for existing address objects and service objects matching `192.0.2.50` and `198.51.100.20`.
  2. Input required parameters into Provisioner module: source subnet `192.0.2.50/32`, destination subnet `198.51.100.20/32`, service ports `22,443`, source interface `port2`, destination interface `port1`, and action `accept`.
  3. Review generated FortiOS CLI block for proper object definitions (`config firewall address`), service group syntax (`config firewall service custom`), and policy positioning (`config firewall policy`).
  4. Perform compliance checklist audit against generated snippet to ensure logging is enabled (`set logtraffic all`) and no wildcard source interfaces are used.

- **App Features Present**:
  - **API Route**: `POST /api/provisioner/generate-fortigate-config` ([routers/provisioner.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/provisioner.py))
  - **API Route**: `POST /api/analyzer/config` ([routers/analyzer.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/analyzer.py))
  - **MCP Tools**: `generate_fortigate_config`, `analyze_config` ([routers/mcp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mcp.py))
  - **UI Module**: Config Generator & Security Analyzer (`static/js/provisioning.js`, `static/js/analyzer.js`)

- **Missing Features / Gaps**:
  - **Automated Direct Push**: No automated transactional push mechanism (REST API `CMDB` commit with auto-rollback on connection loss). Manual CLI paste required.
  - **Shadow Policy Detector**: Provisioner does not check if an existing higher-priority rule already permits or denies the traffic pattern before generating new policy blocks.

---

## 2. Campus Network MAC Tracing & Rogue Host Isolation

### Q2.1: Security alert flags suspicious MAC address `AA:BB:CC:DD:EE:FF`. How to locate physical switch port, connected VLAN, and resolved IP address across campus switches?

- **Answer**:
  1. Initiate MAC location query for `AA:BB:CC:DD:EE:FF` across indexed network devices.
  2. System queries MAC address tables across access, distribution, and core switches using SNMP/SSH drivers.
  3. Filter out trunk/uplink port matches by cross-referencing LLDP/CDP neighbor relationships to isolate edge access port (e.g., `switch-01` port `GigabitEthernet1/0/14`, VLAN 10).
  4. Query network ARP tables and FortiGate DHCP leases to resolve MAC address `AA:BB:CC:DD:EE:FF` to IP address `192.0.2.88`.
  5. Render client map displaying switch topology node, edge port ID, hostname, and active IP binding.

- **App Features Present**:
  - **API Route**: `GET /api/mac/locate` ([routers/mac.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mac.py))
  - **API Route**: `GET /api/mac/mac-to-ip` ([routers/mac.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mac.py))
  - **API Route**: `GET /api/mac/client-map` ([routers/mac.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mac.py))
  - **MCP Tools**: `locate_mac`, `search_mac`, `mac_to_ip`, `client_map` ([routers/mcp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mcp.py))
  - **UI Module**: MAC Locator & Client Mapping dashboard (`static/js/mac.js`)

- **Missing Features / Gaps**:
  - **Automated Port Shutdown Remediation**: Lacks single-click API button or MCP tool to execute `shutdown` or change VLAN assignment (Quarantine VLAN) on identified switch port.
  - **802.1X / RADIUS Telemetry Integration**: Does not pull RADIUS authentication history (username, EAP method, posture state) associated with MAC address from Cisco ISE or FreeRADIUS.

---

### Q2.2: An unassigned IP range `192.0.2.128/25` shows abnormal activity. How to execute subnet ARP discovery and populate endpoint inventory?

- **Answer**:
  1. Trigger multi-threaded ARP scan against target CIDR `192.0.2.128/25` across gateway interfaces or local collector sockets.
  2. Aggregate returned ARP response tuples `(IP, MAC, Vendor OUI, Interface, Response Time)`.
  3. Cross-reference discovered endpoints against baseline endpoint inventory (`/api/endpoint-inventory`).
  4. Flag uncataloged IP/MAC bindings as "Unassigned/Unknown Host".
  5. Store scan results to database for temporal drift analysis.

- **App Features Present**:
  - **API Route**: `POST /api/arp/scan` ([routers/arp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/arp.py))
  - **API Route**: `GET /api/endpoint-inventory` ([routers/endpoint_inventory.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/endpoint_inventory.py))
  - **MCP Tools**: `arp_scan` ([routers/mcp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mcp.py))
  - **UI Module**: ARP Scanner & Endpoint Inventory view (`static/js/arp.js`)

- **Missing Features / Gaps**:
  - **Active OS Fingerprinting**: Uses ARP ping response only; does not perform active Nmap TCP/UDP OS fingerprinting or HTTP banner grabbing to determine device type.
  - **DHCP Snooping Cross-Check**: Cannot inspect DHCP snooping database on switches to verify if ARP response is spoofed.

---

## 3. Wireless LAN Client Disconnects & Rogue AP Containment

### Q3.1: Executive user on MAC `00:11:22:33:44:55` experiences frequent Wi-Fi disconnects on Cisco WLC `192.0.2.10`. How to troubleshoot wireless health and AP association history?

- **Answer**:
  1. Query Cisco WLC live status endpoint for target controller IP `192.0.2.10`.
  2. Perform client detail lookup for client MAC `00:11:22:33:44:55`.
  3. Analyze telemetry fields: connected AP name (`ap-building-a`), SSID/WLAN ID, radio band (2.4 GHz vs 5 GHz vs 6 GHz), RSSI (`-78 dBm` - weak signal alert), SNR (`14 dB`), bytes transferred, and association status.
  4. Run automated WLC client diagnostic pipeline to check for status flags (Authentication failure, DHCP timeout, EAPOL handshake failure, low RSSI roaming issue).
  5. Inspect AP summary on `ap-building-a` for client density and Channel Utilization metrics.

- **App Features Present**:
  - **API Route**: `GET /api/wlc/{ip}/client/{mac}` ([routers/wlc.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/wlc.py#L51-L53))
  - **API Route**: `GET /api/wlc/{ip}/diagnose-client/{mac}` ([routers/wlc.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/wlc.py))
  - **API Route**: `GET /api/wlc/{ip}/ap-summary` ([routers/wlc.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/wlc.py#L43-L45))
  - **MCP Tools**: `wlc_client_detail`, `wlc_diagnose_client`, `wlc_ap_summary` ([routers/mcp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mcp.py))

- **Missing Features / Gaps**:
  - **Dashboard UI Tab (`wlc.js`)**: Lacks dedicated WLC frontend tab in web dashboard (`templates/dashboard.html`); WLC endpoints are accessible only via REST API, MCP tools, or AI Assistant.
  - **802.11 Roaming Event Timeline**: Does not retain historical log of fast roaming transitions (802.11r/k/v) between APs over time.
  - **AP RF Heatmap Visualization**: Displays tabular AP summary metrics without spatial floor plan coverage overlay.

---

### Q3.2: Rogue Access Point detected on site premises broadcasting spoofed corporate SSID. How to locate and evaluate threat severity?

- **Answer**:
  1. Query WLC rogue AP detector endpoint for target WLC controller `192.0.2.10`.
  2. Parse detected rogue entries: Rogue BSSID, SSID name, channel, RSSI heard by monitoring APs, rogue status (`Unclassified`, `Malicious`, `Friendly`).
  3. Query FortiGate managed FortiAP wireless client and AP telemetry (`/api/fortigate/{ip}/managed-aps`) to check if FortiWiFi infrastructure also detects rogue signals.
  4. Identify detecting APs with highest RSSI to isolate physical location of rogue transmitter.
  5. Check if rogue BSSID is observed on wired MAC address tables to rule out rogue AP connected to internal LAN switch port.

- **App Features Present**:
  - **API Route**: `GET /api/wlc/{ip}/rogue-aps` ([routers/wlc.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/wlc.py#L59-L61))
  - **API Route**: `GET /api/fortigate/{ip}/managed-aps` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py))
  - **MCP Tools**: `wlc_rogue_aps`, `fortigate_managed_aps` ([routers/mcp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mcp.py))

- **Missing Features / Gaps**:
  - **Dashboard UI Tab**: No dedicated WLC UI view in web dashboard; rogue AP telemetry currently relies on MCP tool / API calls.
  - **Active Rogue Containment Trigger**: Cannot send API command to trigger 802.11 deauthentication frame injection / wire containment from WLC.
  - **Automated Switch Port Auto-Block for Wired Rogue**: Cannot automatically disable switch port matching rogue MAC on wired network.

---

## 4. Network Traffic Anomalies, Top Talkers & DDoS / Session Drain Response

### Q4.1: Internal subnet experiences high latency. How to identify top bandwidth-consuming endpoints and detect traffic anomalies?

- **Answer**:
  1. Query Flow SIEM NetFlow/sFlow collector endpoint for top talkers over past 15-minute window.
  2. Inspect top talker breakdown by Source IP, Destination IP, Protocol, Destination Port, Total Bytes, and Packet Count.
  3. Query flow anomaly detector endpoint to check for flagged traffic patterns (e.g., sudden bandwidth spike from host `192.0.2.210` hitting `198.51.100.99` on UDP port `443` exceeding baseline threshold by 400%).
  4. Perform FortiGate live session query for host `192.0.2.210` to inspect active session counts and concurrent connection rates.
  5. Formulate mitigation plan (rate limiting or shun policy).

- **App Features Present**:
  - **API Route**: `GET /api/flow-siem/top-talkers` ([routers/flow_siem.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/flow_siem.py))
  - **API Route**: `GET /api/flow-siem/anomalies` ([routers/flow_siem.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/flow_siem.py))
  - **MCP Tools**: `get_top_talkers`, `get_anomalies`, `fortigate_sessions` ([routers/mcp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mcp.py))
  - **UI Module**: Flow SIEM & Live Traffic Analytics Dashboard (`static/js/flow_siem.js`)

- **Missing Features / Gaps**:
  - **Automated ACL / Null-Route Injection**: Lacks one-click automated action to inject BGP Flowspec or local ACL rule to block offending IP `192.0.2.210`.
  - **Encrypted Traffic Analysis (JA3 / SNI)**: NetFlow collector parses standard L3/L4 headers but does not extract TLS Client Hello SNI or JA3 hashes for encrypted flow classification.

---

### Q4.2: FortiGate firewall CPU reaches 95% due to session table saturation. How to identify session hogs and drain stale connections?

- **Answer**:
  1. Fetch FortiGate system status and resource summary (`/api/fortigate/{ip}/status`) to verify CPU, RAM, and session table usage (% of max session capacity).
  2. Query active session list grouped by top source IP to isolate IP addresses creating disproportionate session allocations (e.g., host `192.0.2.14` holding 45,000 concurrent TCP connections).
  3. Inspect policy stats (`/api/fortigate/{ip}/policy-stats`) to identify which firewall policy rule handles session-heavy traffic.
  4. Verify if sessions are stuck in `CLOSE_WAIT` or `SYN_RECV` states indicative of SYN flood or improper TCP termination.
  5. Issue targeted CLI diagnosis command via app CLI runner to clear session table entries for offending source IP.

- **App Features Present**:
  - **API Route**: `GET /api/fortigate/{ip}/status` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py))
  - **API Route**: `POST /api/fortigate/{ip}/sessions/query` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py#L54-L59))
  - **API Route**: `GET /api/fortigate/{ip}/policy-stats` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py))
  - **API Route**: `POST /api/commands/send` ([routers/commands.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/commands.py))
  - **MCP Tools**: `fortigate_status`, `fortigate_sessions`, `fortigate_policy_stats`, `send_cli_command` ([routers/mcp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mcp.py))

- **Missing Features / Gaps**:
  - **Targeted API Session Kill Endpoint**: Direct REST API endpoint to terminate sessions matching criteria (`DELETE /api/fortigate/{ip}/sessions?src=...`) is missing; must execute raw CLI command (`diagnose sys session filter ...`).
  - **Automated Session Threshold Alerts**: Lacks configurable webhooks to trigger paging alerts when session utilization crosses 85% threshold.

---

## 5. Incident Response, Flow SIEM & Endpoint Threat Correlation

### Q5.1: High-priority SIEM alert indicates potential port scan or C2 beaconing from internal IP `192.0.2.77`. How to conduct incident triage?

- **Answer**:
  1. Open Incidents module (`/api/incidents`) and fetch incident record associated with host `192.0.2.77`.
  2. Query Triage Status endpoint (`/api/triage/status`) to execute automated heuristic check across network indicators.
  3. Review Flow SIEM events matching `192.0.2.77` to inspect outbound connection attempts to distinct external destination IPs across sequential destination ports.
  4. Perform MAC location lookup on `192.0.2.77` to identify physical switch port (`switch-02`, port `Gi1/0/8`) and AP/WLAN if wireless.
  5. Trigger AI-Assisted Triage Diagnosis (`/api/ai/diagnose`) to generate root cause analysis, severity score, and mitigation recommendations.

- **App Features Present**:
  - **API Route**: `GET /api/incidents` ([routers/incidents.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/incidents.py))
  - **API Route**: `GET /api/triage/status` ([routers/triage.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/triage.py))
  - **API Route**: `POST /api/ai/diagnose` ([routers/ai.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/ai.py))
  - **MCP Tools**: `get_triage_status`, `locate_mac`, `get_anomalies` ([routers/mcp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mcp.py))
  - **UI Module**: Incident Response & AI Triage Center (`static/js/incidents.js`, `static/js/ai.js`)

- **Missing Features / Gaps**:
  - **External Threat Intel API Integration**: Does not automatically query AbuseIPDB, VirusTotal, or AlienVault OTX for reputational scoring of destination IPs in flow logs.
  - **SOAR Webhook Export**: Lacks native webhook integration to push incident triage states automatically to external platforms (ServiceNow, Jira, Slack).

---

## 6. Security Compliance Audit, Rule Drift & Configuration Provisioning

### Q6.1: How to perform security compliance audit on FortiGate or Cisco switch configurations to detect weak ciphers, permissive rules, and default credentials?

- **Answer**:
  1. Upload or select stored configuration backup file in Config Analyzer (`/api/analyzer/config`).
  2. Run static parser engine against configuration ruleset.
  3. Check parser output for security violations:
     - Telnet or HTTP management enabled.
     - Weak SSH ciphers / SNMP v1/v2c community strings (`public`/`private`).
     - Any-to-Any firewall policies without logging enabled (`set srcaddr all`, `set dstaddr all`, `set service ALL`).
     - Missing admin password encryption (`service password-encryption` disabled).
  4. Cross-reference findings against default Security Audit Checklist template (`/api/audit-checklist`).
  5. Export remediation recommendations and compliance score.

- **App Features Present**:
  - **API Route**: `POST /api/analyzer/config` ([routers/analyzer.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/analyzer.py))
  - **API Route**: `GET /api/audit-checklist` ([routers/audit_checklist.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/audit_checklist.py))
  - **API Route**: `GET /api/backup` ([routers/backup.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/backup.py))
  - **MCP Tools**: `analyze_config` ([routers/mcp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mcp.py))
  - **UI Module**: Security Compliance & Config Analyzer (`static/js/analyzer.js`, `static/js/audit_checklist.js`)

- **Missing Features / Gaps**:
  - **PCI-DSS / CIS Benchmark Mapping Tagging**: Rules are categorized generically; lacks explicit mapping tags to PCI-DSS v4.0, NIST SP 800-53, or CIS Controls sections.
  - **Automated Drift Alerting on Git Backup**: Backup module stores configs, but does not auto-commit to Git repo with line-by-line diff notifications when configuration changes unexpectedly outside maintenance windows.

---

## 7. Multi-Site VPN & Inter-VLAN Connectivity Troubleshooting

### Q7.1: Inter-site IPsec VPN tunnel between Main Site (`192.0.2.1`) and Branch Site (`198.51.100.1`) is down. How to troubleshoot IPsec phase 1/2 and routing?

- **Answer**:
  1. Query Sites list (`/api/sites`) and Network Map (`/api/topology/map`) to review cross-site link topology and gateway assignments.
  2. Fetch FortiGate interface and IPsec tunnel status for gateway `192.0.2.1` (`/api/fortigate/{ip}/interfaces`).
  3. Check static route table on `192.0.2.1` (`/api/fortigate/{ip}/routes`) to verify remote branch subnet `198.51.100.0/24` points to active IPsec virtual interface.
  4. Query FortiGate traffic logs for IKE protocol traffic (UDP port `500` / `4500`) matching remote peer gateway `198.51.100.1` to identify Phase 1 negotiation failures (pre-shared key mismatch, proposal mismatch, main/aggressive mode mismatch).
  5. Execute ping monitor test from app server to remote site management interface to test ICMP reachability.

- **App Features Present**:
  - **API Route**: `GET /api/sites` ([routers/sites.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/sites.py))
  - **API Route**: `GET /api/topology/map` ([routers/topology.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/topology.py))
  - **API Route**: `GET /api/fortigate/{ip}/interfaces` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py))
  - **API Route**: `GET /api/fortigate/{ip}/routes` ([routers/fortigate.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/fortigate.py))
  - **MCP Tools**: `list_sites`, `get_network_map`, `fortigate_interfaces`, `fortigate_routes` ([routers/mcp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mcp.py))

- **Missing Features / Gaps**:
  - **IPsec IKE Debug Telemetry API**: Does not execute dynamic `diagnose debug application ike -1` command stream via REST API; relies on traffic logs and interface UP/DOWN status.
  - **BGP / OSPF Neighbor State Telemetry**: Lacks dedicated API parser for dynamic routing protocol neighbor adjacency status (e.g., BGP ESTABLISHED / OSPF FULL).

---

## 8. Infrastructure Health & Monitoring Triage

### Q8.1: Linux collector server hosting SentinelNet flow listeners reports CPU/disk degradation. How to assess health state?

- **Answer**:
  1. Query Linux Health endpoint (`/api/observability/linux-health`) for targeted collector node.
  2. Inspect core metrics: CPU usage (user, system, idle), RAM utilization, swap usage, disk partition space (`/` and `/var/log`), and system load averages (1m, 5m, 15m).
  3. Verify status of critical collector services (`flow_collector`, `syslog_listener`, `ping_monitor`).
  4. If disk space exceeds 90% threshold due to accumulated flow logs, trigger log rotation or database maintenance cycle.

- **App Features Present**:
  - **API Route**: `GET /api/observability/linux-health` ([routers/observability.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/observability.py))
  - **API Route**: `GET /api/observability/status` ([routers/observability.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/observability.py))
  - **MCP Tools**: `linux_health` ([routers/mcp.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/routers/mcp.py))
  - **UI Module**: System Health & Observability tab (`static/js/observability.js`)

- **Missing Features / Gaps**:
  - **Automated Log Purge Trigger**: High disk utilization detected in health check requires manual SSH log deletion; auto-pruning policies based on disk watermark missing.

---

## Summary Matrix of Capabilities vs Gaps

| Domain | Present App Features | Key Missing Features / Gaps |
| :--- | :--- | :--- |
| **FortiGate Firewalls** | Policy lookup, live sessions, traffic logs, managed FortiAP/WiFi, config backups, REST/SSH driver | Raw packet capture (`sniffer`), deep UTM sub-log UI parsing, direct API policy modification |
| **Cisco WLC (AireOS/9800)** | AP summary, wireless client details, WLAN lists, rogue AP detection, client diagnostic path | 802.11 roaming history timeline, RF floorplan heatmaps, wireless rogue active containment trigger |
| **MAC & IP Tracing** | Multi-vendor switch port locator, ARP ping scanner, MAC-to-IP resolution, client map visualization | Automated switch port shutdown/remediation, 802.1X/RADIUS auth log correlation |
| **Flow SIEM & Anomalies** | NetFlow/sFlow ingestion, top talkers aggregation, flow anomaly detection engine, SIEM event log | Automated IP shun/block trigger, TLS JA3/SNI encrypted flow inspection, external Threat Intel scoring |
| **Config & Compliance** | FortiOS/IOS-XE static analyzer, config backup diffs, ACL generator, security audit checklists | Direct commit push with auto-rollback, PCI-DSS/CIS benchmark tagging, real-time Git drift alerts |

