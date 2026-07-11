# ZTP (Zero-Touch Provisioning) — Implementation Notes

> **Coverage caveat:** The supplied pages (633, 645, 3228, 3253, 3337, 3354, 3636, 4076) contain no dedicated ZTP chapter (no FortiDeploy/FortiZTP/DHCP-option-based provisioning content). Below is everything ZTP-adjacent that is present: day-0 bootstrap config scripting (VM), FortiGuard central-management provisioning hooks, LTE/WWAN bring-up verification, and post-provision verification commands your tool can use to confirm a device came up correctly.

---

## 1. Day-0 / bootstrap config script (VM, page 4076)

FortiGate-VM accepts an injected config script at first boot (cloud-init/user-data style). Script is plain CLI, executed line-by-line (`$` prompt echo shown per line, ends with `Finish running config script`). Canonical bootstrap sequence:

```
config system admin
    edit admin
        set password 12345678
    end

config system interface
    edit port1
        set mode static
        set ip 10.6.30.169/24
        set allowaccess ping https ssh snmp http telnet fgfm radius-acct probe-response ftm
    next
    edit port2
        set mode static
        set ip 10.1.100.169/24
        set allowaccess ping https ssh snmp http telnet fgfm radius-acct probe-response ftm
    next
    edit port3
        set mode static
        set ip 172.16.200.169/24
        set allowaccess ping https ssh snmp http telnet fgfm radius-acct probe-response ftm
    next
end

config firewall policy
    edit 0                       # edit 0 = auto-assign next free policy ID
        set srcintf "port2"
        set dstintf "port3"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
    next
end

config router static
    edit 1
        set gateway 172.16.200.254
        set device "port3"
        # destination defaults to 0.0.0.0/0 (all IPs) when unset
    next
end
```

**Gotchas:**
- `set ip a.b.c.d/24` (CIDR) and `set ip a.b.c.d 255.255.255.0` (mask) are both accepted in `config system interface`.
- `set allowaccess` is a full replace, not additive — always include `https ssh` (REST/CLI access) and `fgfm` (FortiManager/central-mgmt tunnel) or you lock out your tool.
- Static route with no `set dst` = default route `0.0.0.0/0`.

## 2. Central management / FortiGuard provisioning hooks (page 645)

Devices phoning home to FortiGuard for management use:

```
config system central-management
    set type fortiguard
end
```

LTE modem firmware auto-upgrade scheduling under the same stanza (relevant if ZTP flow includes modem fw baseline):

```
# One-time:
set ltefw-upgrade-time <YYYY-MM-DD HH:MM:SS>

# Recurring (interval enum is exact):
set ltefw-upgrade-frequency {everyHour | every12hour | everyDay | everyWeek}

# Disable remote LTE fw upgrades entirely:
set allow-remote-lte-firmware-upgrade disable
```

## 3. Post-provision verification commands (SSH fallback path)

Your tool should confirm a freshly provisioned box got addressing/routing. Exact CLI:

```
diagnose ip address list
# Output format: IP=<ip>-><ip>/<mask> index=<n> devname=<ifname>
# e.g. IP=10.34.139.21->10.34.139.21/255.255.255.255 index=23 devname=wwan

diagnose ipv6 address list
# Output: dev=<n> devname=<if> flag=<F> scope=<n> prefix=<len> addr=<v6> preferred=... valid=...

get router info routing-table all
# Codes: K kernel, C connected, S static, R RIP, B BGP, O OSPF, i IS-IS, * candidate default
# e.g. S* 0.0.0.0/0 [10/0] via 10.34.139.22, wwan, [1/0]
```

WWAN/LTE bring-up indicators (page 633): interface gets /32 IPv4 + auto default route; IPv6 GW prefixlen 64; MTU 1500; link protocol `QMI_WDA_LINK_LAYER_PROTOCOL_RAW_IP`; autoconnect `QMI_WDS_AUTOCONNECT_DISABLED`.

## 4. ZTP-relevant `allowaccess` tokens (for interface templates)

Observed valid tokens: `ping https ssh snmp http telnet fgfm radius-acct probe-response ftm fabric`.
- `fgfm` — required for FortiManager/FortiGuard management tunnel (ZTP-critical).
- `fabric` — required on Security Fabric downstream-facing interfaces (page 3636):

```
config system csf
    set status enable
    set group-name "CSF_E"
end
```

## 5. HA-aware provisioning (page 3228)

If ZTP target is an HA pair, dedicated mgmt interface per node so your tool can reach each unit independently:

```
config system ha
    set group-name "test-ha"
    set mode a-p
    set password *****
    set hbdev "port6" 50
    set hb-interval 4
    set hb-lost-threshold 10
    set session-pickup enable
    set ha-mgmt-status enable
    config ha-mgmt-interfaces
        edit 1
            set interface "mgmt1"
        next
    end
    set override enable
    set priority 200        # secondary: 100
    set ha-direct enable    # mgmt traffic (NetFlow/SNMP/etc.) sourced from ha-mgmt iface
end

config system interface
    edit "mgmt1"
        set ip 10.6.30.111 255.255.255.0     # secondary: 10.6.30.112
        set allowaccess ping https ssh http telnet fgfm
        set type physical
        set dedicated-to management
        set role lan
    next
end
```

NetFlow export (only configured on primary; synced):

```
config system netflow
    set collector-ip 10.6.30.59
end
```

**Gotcha:** with `ha-direct enable`, NetFlow/telemetry sources from the ha-mgmt interface IP — collector ACLs must permit both node mgmt IPs.

## 6. SNMP traps useful for ZTP completion detection (page 3354)

- **linkUp/linkDown** (SNMPv1 trap, UDP/162): carries `IF-MIB::ifIndex`, `ifAdminStatus` (up(1)/down(2)), `ifOperStatus`, `FORTINET-CORE-MIB::fnSysSerial.0` (device serial — use as ZTP identity key), `sysName.0`.
- **fgFmTrapIfChange** (`FORTINET-FORTIGATE-MIB`): fired on any interface change, incl. IP assignment. Payload: `IF-MIB::ifName`, `fgManIfIp.0`, `fgManIfMask.0`, `fgManIfIp6.0`. Good signal that day-0 addressing landed.

## 7. Notes for the Python tool

- REST API endpoints for ZTP are not covered in these pages; for the config objects above, the standard mappings are `cmdb` paths mirroring CLI stanzas (e.g. `system/central-management`, `system/interface`, `system/ha`, `system/netflow`, `system/csf`, `router/static`, `firewall/policy`) — verify against the FNDN API reference before hardcoding.
- Parse `diagnose ip address list` lines with regex `^IP=(\S+)->(\S+)/(\S+) index=(\d+) devname=(\S+)$` for the SSH fallback.
- Trap listener: bind UDP/162; key inventory on `fnSysSerial` (e.g. `FG140P3G15800330` format).