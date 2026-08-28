# Reference

External vendor documentation, distilled to what SentinelNet actually needs.
These are notes taken *from* someone else's documentation, not descriptions of
this codebase — they change only when the vendor's product does.

## FortiOS 7.4.12

| Document | Covers |
|---|---|
| [fortios/rest-api.md](fortios/rest-api.md) | API user creation, token auth, endpoints used by `services/fortigate_service.py` |
| [fortios/logging.md](fortios/logging.md) | Syslog configuration, log formats, the `key=value` body the syslog parser expects |
| [fortios/wifi.md](fortios/wifi.md) | Wireless controller concepts relevant to the WLC views |
| [fortios/ztp.md](fortios/ztp.md) | Zero-touch provisioning, used by `services/fortigate_provisioner.py` |

Note the version: these notes were distilled against FortiOS 7.4.12. Check them
against the running firmware before trusting a CLI syntax detail.

## Cisco Catalyst

| Document | Covers |
|---|---|
| [cisco/snmp-mibs.md](cisco/snmp-mibs.md) | MIB support matrix for Catalyst 9200/9300/9400/9500, and the verdict on every OID `snmp_poller.py` queries |
| [cisco/programmability.md](cisco/programmability.md) | NETCONF/RESTCONF preconditions and the diagnostic order when `mac_collector.py` silently falls back to CLI |
| [cisco/ipv4-acls.md](cisco/ipv4-acls.md) | ACL evaluation order, VLAN-map precedence, ACE syntax, and what `services/policy_test/` does and does not model |
| [cisco/system-messages.md](cisco/system-messages.md) | IOS-XE syslog message structure, severity mapping, and what the 17.18 catalog does and doesn't contain |

Sources: MIB data scraped from Cisco's published support lists; the rest
distilled from the IOS-XE 17.18 Programmability Command Reference, System
Message Guide, and Catalyst 9200 Security Configuration Guide. 17.18 is likely **ahead of any deployed train**, so each document
flags which statements are version-sensitive and cites the release that
introduced each command.
