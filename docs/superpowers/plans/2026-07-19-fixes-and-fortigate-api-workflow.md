# 2026-07-19 — Fixes + FortiGate API workflow

## Phase 1 — Fixes (parallel subagents, in flight)
1. **VTP mode in minimal 2D map** — `static/js/topology.js` ~L1018: label shows only `vtp_domain`; append mode (`domain · mode`) like classic card (L244).
2. **AI "Genera config nuovo switch": tenant select empty** — `static/js/ai.js` populateGenCfgTenants / loadAiTab path; systematic debug (i18n keys, exception before L75, repopulation timing).
3. **FortiGate REST test SSL verify failed** — trace test path in `routers/fortigate.py` / `fortigate_service.py`; honor stored `verify_tls` (default False, self-signed FGT certs); clearer SSLCertVerificationError message.

## Phase 2 — FortiGate API workflow (from Fortinet "Using APIs" doc)
Goal: make the stored API token actually useful beyond the connection test.

Design (REST-primary, SSH-fallback per existing architecture; token via
`Authorization: Bearer` header — already the pattern in fortigate_service.py):

1. **`fortigate_service.py`**: add `api_get_cmdb(ip, path, fmt=None, flt=None)`
   thin wrapper on existing `_api_get` supporting `format` and `filter` query
   params (doc: `?format=name|comment`, `filter=name=@X`) to slim payloads.
2. **New read-only inventory calls** on the analyzer Firewall tab (FortiGate
   vendor sub-tabs already generic):
   - Address objects: `api/v2/cmdb/firewall/address?format=name|type|subnet|fqdn|comment`
   - Policies: `api/v2/cmdb/firewall/policy?format=policyid|name|srcintf|dstintf|srcaddr|dstaddr|service|action|status|logtraffic`
   - Services: `api/v2/cmdb/firewall.service/custom?format=name|tcp-portrange|udp-portrange|comment`
   Router endpoints in `routers/fortigate.py` (auth + assert_device_allowed),
   frontend tables with client-side filter box (escapeHtml(jsStr(x)) convention).
3. **MCP tools**: expose the same three reads in `mcp_server.py` so the AI
   assistant can query addresses/policies during chat.
4. Tests: extend `test_fortigate_service.py` (mock requests) + openapi parity
   snapshot update.

Out of scope: write/CRUD to FortiGate (delete/create policies) — read-only for now.

## Phase 3 — Verify + ship
- Run full test suite, `graphify update .`
- /security-review of branch
- Rebuild exe: `pyinstaller SentinelNet.spec`
- Merge new_dev → master (user-gated)
