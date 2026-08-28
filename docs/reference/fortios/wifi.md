# FortiOS 7.4.12 — WiFi Implementation Notes

## SSID interface (`Network > Interfaces` / WiFi & Switch Controller > SSIDs)
- SSID is an interface type `WiFi SSID` (CLI type: `vap-switch`). Created under **WiFi & Switch Controller > SSIDs**; then appears in `Network > Interfaces` and via the standard interface API (`/api/v2/cmdb/system/interface`).
- **Traffic mode** (only when Type = WiFi SSID):
  - `Tunnel` — tunnel to wireless controller
  - `Bridge` — local bridge with FortiAP's interface
  - `Mesh` — mesh downlink
- Addressing modes: Manual, DHCP, Auto-managed by IPAM, PPPoE (entry-level models only), One-Arm Sniffer. Interfaces cannot have multiple IPs on the same subnet.
- Interface `role` affects which GUI settings appear (LAN default; WAN hides DHCP server/Security mode/Dedicate-to-extension-fortiap etc.) — irrelevant for API reads but explains missing fields.

## IPAM for SSIDs
```text
config system ipam
    set manage-ssid-addresses {enable | disable}   # default: disable
end
```
- Wireless network interfaces (`vap-switch` type) auto-receive IPAM addresses when enabled; no per-interface config needed.
- Per-interface override:
```text
config system interface
    edit <name>
        set ip-managed-by-fortiipam {enable | disable | inherit-global}   # default inherit-global
    next
end
```

## WiFi dashboard widgets / monitors (`Dashboard > WiFi`)
Widgets available (each expandable to full-screen monitor, saveable as monitor):
- Channel Utilization, Clients By FortiAP, FortiAP Status, Historical Clients, Interfering SSIDs, Login Failures, Rogue APs, Signal Strength, Top WiFi Clients
- **FortiAP Status monitor**: status + per-radio channel utilization; right-click AP → *Diagnostics and Tools* (tabs: Clients, Spectrum Analysis, VLAN Probe, health metrics — same dialog as WiFi & Switch Controller > Managed FortiAPs).
- **Clients by FortiAP monitor**: per-client connection health; right-click client → *Diagnostics and Tools*.
- WiFi dashboard supports the Security Fabric device dropdown (view downstream Fabric FortiGate dashboards, login/configure devices).

## FortiAP authorization / Fabric
- New FortiAPs appear gray (unauthorized) in Security Fabric Physical/Logical Topology; click icon → *Authorize* (turns blue). Right-click authorized FortiAP → *Deauthorize* or *Restart*.
- Registration via `System > Firmware & Registration` (select unregistered device → Register).
- If `auto-auth-extension-device` default was modified on the FortiAP, manual authorization may not be required.
- FortiAP IPs (from FortiAP Setup pane or DHCP) auto-populate the built-in `FABRIC_DEVICE` firewall address object — usable as `dstaddr` in policies.
- Verify Fabric device IPs:
```text
diagnose firewall sf-addresses list     # shows FortiAP / FortiAP/SW-DHCP entries
diagnose ipsp mefabric-address list     # IPs used in security policy
```

## FortiAP → FortiGuard IoT device query
Requires Attack Surface Security Rating license. FortiAP collects packets, queries FortiGuard via the FortiGate; results shown on FortiGate.
```text
config wireless-controller setting
    set device-weight <0-255>    # confidence upper limit; default 1, 0=disable
    set device-holdoff <0-60>    # min creation time, minutes; default 5
    set device-idle <0-14400>    # max idle time, minutes; default 1440
end
```
Inspect detected devices:
```text
diagnose user device list
# shows: MAC, ip, srcmac, hardware vendor/type/family (src fortiguard, weight),
# os (src dhcp), host, port, age
```

## FortiAP EOS (end-of-support) data
```text
diagnose fortiguard-resources update fortiap-end-of-support
```
- Auto-downloaded at bootup; run manually if download failed. EOS devices highlighted red with status `EOS - Unable to upgrade` on `System > Firmware & Registration`, in Fabric topology pages, and the Status dashboard System Information widget.

## Quarantine / automation (WiFi-relevant)
- Compromised hosts behind a FortiAP can be quarantined from topology view (host shown red; tooltip shows IoC verdict).
- Built-in stitch action for quarantine on access layer (FortiSwitch + FortiAP):
```text
config system automation-action
    edit "Access Layer Quarantine"
        set action-type quarantine
    next
end
config system automation-trigger
    edit "Incoming Webhook Call"
        set event-type incoming-webhook
    next
end
```
(Incoming webhook can drive MAC quarantine on FortiAPs/FortiSwitches/EMS.)

## Security Rating
- FortiAP firmware version check contributes to Security Fabric score (weights: Critical 50, High 25, Medium 10, Low 5). No FortiAPs in Fabric → check neither adds nor subtracts points.
- IoT vulnerability rating check available under `Security Fabric > Security Rating` (uses FortiGuard IoT vuln lookup).

## Gotchas
- StateRamp-licensed FortiGates: **FortiAP pre-authorization is allowed**, but FortiAP-related automation stitches/triggers/actions are limited; unsupported features return errors in GUI/CLI. Check license: `get system status` → `License Status: StateRAMP`.
- SD-Branch: FortiAP sits at the "network access" layer of SD-WAN architecture (wireless segmentation + built-in NAC); management/orchestration via FortiManager REST API.
- SSID interfaces cannot be HA heartbeat interfaces (heartbeat only on physical interfaces — not switch ports, VLANs, IPsec, redundant, or 802.3ad aggregates).
- NAC policies can dynamically move vulnerable IoT devices (detected via FortiAP/IoT query) to a quarantine VLAN.
- IoT application signatures: `get application name status | grep IoT -B2 -A10`.