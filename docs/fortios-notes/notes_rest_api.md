# FortiOS 7.4.12 — REST API Implementation Notes

## Authentication
- Create a REST API user (`config system api-user`) → use generated API token as Bearer token:
  ```
  curl -k -X POST -H 'Authorization: Bearer <api-token>' ...
  ```
- API user config example (with trusted hosts and admin profile):
  ```
  config system api-user
      edit "api"
          set api-key ************
          set accprofile "api_profile"
          set vdom "root"
          config trusthost
              edit 1
                  set ipv4-trusthost 10.6.30.0 200.200.200.0
              next
          end
      next
  end
  ```

## SD-WAN monitoring endpoints (GET)
| Purpose | Endpoint |
|---|---|
| Interface log | `https://<fgt>/api/v2/monitor/virtual-wan/interface-log` |
| SLA log | `https://<fgt>/api/v2/monitor/virtual-wan/sla-log` |
| Health check log | `https://<fgt>/api/v2/monitor/virtual-wan/health-check` |

- Used by FortiManager for SLA drilldown; full API list on Fortinet Developer Network.
- CLI fallback (per-port interface SLA log):
  ```
  diagnose sys sdwan intf-sla-log port13
  ```
  Output fields per line: `Timestamp`, `used inbandwidth` (bps), `used outbandwidth` (bps), `used bibandwidth` (bps), `tx bytes`, `rx bytes`. ~10 s sampling interval.

## Certificate upload endpoints (POST, JSON body)
Certificate content must be **Base64-encoded**. Not all params are required per method; `*` = default.

- `api/v2/monitor/vpn-certificate/ca/import`
  ```json
  {"import_method":"[file|scep]","scep_url":"string","scep_ca_id":"string",
   "scope":"[vdom*|global]","file_content":"string"}
  ```
- `api/v2/monitor/vpn-certificate/crl/import`
  ```json
  {"scope":"[vdom*|global]","file_content":"string"}
  ```
- `api/v2/monitor/vpn-certificate/local/import`
  ```json
  {"type":"[local|pkcs12|regular]","certname":"string","password":"string",
   "key_file_content":"string","scope":"[vdom*|global]",
   "acme-domain":"string","acme-email":"string","acme-ca-url":"string",
   "acme-rsa-key-size":0,"acme-renew-window":0,"file_content":"string"}
  ```
- `api/v2/monitor/vpn-certificate/remote/import`
  ```json
  {"scope":"[vdom*|global]", ...}
  ```

## Automation stitch webhook (incoming)
- Endpoint: `POST /api/v2/monitor/system/automation-stitch/webhook/<stitch-name>`
- **Encode spaces in stitch name as `%20`** (e.g. `Incoming%20Webhook%20Quarantine`).
- Example:
  ```
  curl -k -X POST -H 'Authorization: Bearer cfgtct1mmx0fQxr4khb000p70wdfmk' \
    --data '{ "mac": "0c:0a:00:0c:ce:b0", "fctuid": "3000BB0B0ABD0D00B0D0A0B0E0F0B00B" }' \
    https://100.10.100.200/api/v2/monitor/system/automation-stitch/webhook/Incoming%20Webhook%20Quarantine
  ```
- Success response fields: `http_method`, `status` ("success"), `http_status` (200), `serial`, `version`, `build`.
- Triggering quarantines the MAC on FortiGate; FortiClient UUID quarantined on EMS side; event log created (`logid="0100046600"`, `subtype="system"`, `logdesc="Automation stitch triggered"`).

## Threat feed / external resources — API key auth (outbound)
- API key auth only configurable in CLI via `set user-agent`. Append headers with `\r\n`:
  ```
  config system external-resources
      edit <name>
          set user-agent "Firefox\r\nAPI-Key: abcdef12345"
      next
  end
  ```
- Multiple custom headers supported: `set user-agent "Firefox\r\nheader1: test1\r\nheader2: test2"` — each becomes its own HTTP header in the outgoing request.
- Threat feeds also support **Push API** update method (webhook to FortiGate REST API) with add / remove / snapshot operations. FortiGuard license required if using FortiGuard Category feed in a web filter profile (NGFW profile/policy mode).
- Gotcha: `HTTP/1.1 301 Moved Permanently` responses are not followed — e.g. AusCERT feed URL required a **trailing slash** (`/api/v1/malurl/combo-7-txt/`) to get `200 OK`.
- Debug fetch process: `diagnose debug app forticron -1` (shows full HTTP request, DNS resolution, response status).

## REST API event logging
- Enable in CLI:
  ```
  config log setting
      set rest-api-set enable
      set rest-api-get enable
  end
  ```
- Sample log record (subtype `rest-api`, `logid="0116047301"`):
  ```
  type="event" subtype="rest-api" level="information" vd="root"
  logdesc="REST API request success" user="admin" ui="GUI(192.168.1.69)"
  method="GET" path="system.usb-log" status="200"
  url="/api/v2/monitor/system/usb-log?vdom=root"
  ```
- Useful fields to parse: `method`, `path` (dot-notation, e.g. `log.fortianalyzer.setting`), optional `action` (e.g. `connection`), `status`, `url`.

## Incidentally-documented endpoints (from sample logs)
- `GET /api/v2/monitor/system/usb-log?vdom=root`
- `GET /api/v2/monitor/license/status?vdom=root`
- `GET /api/v2/cmdb/log.fortianalyzer/setting?vdom=root`
- `GET /api/v2/monitor/system/sandbox/connection?vdom=root`
- `GET /api/v2/monitor/system/firmware?vdom=root`

## General gotchas
- Two API trees: `/api/v2/monitor/...` (runtime state/actions) vs `/api/v2/cmdb/...` (configuration objects).
- `?vdom=<name>` query param selects VDOM scope on requests.
- Cert import bodies use `scope: [vdom*|global]` — vdom is default.
- Trusted-host restrictions on `api-user` will reject requests from other source IPs — ensure your tool's source IP is in `trusthost`.