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
