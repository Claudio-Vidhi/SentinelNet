# OT Expansion Phase 2: Passive Discovery, Industrial OUI & Opt-In OT Probes

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Deliver passive industrial asset and protocol visibility without active PLC polling by default, plus opt-in, rate-limited read-only OT identity probes in the remote agent.

**Architecture:**
1. **Industrial OUI Lookup (`collectors/industrial_oui.py` + `collectors/mac_collector.py` + `collectors/mac_history.py`):** Static OUI prefix table covering the 11 target industrial vendors (Siemens, Rockwell/Allen-Bradley, Schneider Electric, Beckhoff, Omron, Moxa, Hirschmann, Phoenix Contact, Wago, Fanuc, ABB). Integrated into MAC collection (`collect_mac_table` / `collect_wlc` in `collectors/mac_collector.py`) and sighting persistence/enrichment (`record_sightings` and `endpoint_inventory` in `collectors/mac_history.py`), preserving any explicit `oui_vendor` already passed by callers. <!-- check-private-data: ok -->
2. **Passive OT Protocol Tagging (`observability/ingesters/ot_protocols.py` + `observability/ingesters/syslog.py` + `observability/fieldmap.py` + `observability/normalize.py`):** Purely passive classification of Modbus TCP (`tcp/502`), S7comm (`tcp/102`), EtherNet/IP (`tcp/44818`, `udp/2222`), OPC-UA (`tcp/4840`), PROFINET (`udp/34964`, `ethertype 0x8892`, DCP/RT keywords), BACnet (`udp/47808`), IEC 60870-5-104 (`tcp/2404`), and DNP3 (`tcp/20000`, `udp/20000`) from flow/syslog/mirror metadata without sending packets to PLCs.
3. **Opt-In Rate-Limited Read-Only OT Probes (`services/probe_agent.py`):** Read-only discovery frame builders, response parsers, and rate-limited probe runners for EtherNet/IP `ListIdentity` (0x0063), Modbus FC 43 / MEI 14 (*Read Device Identification*, `0x2B 0x0E 0x01 0x00` — never coil/register writes), OPC-UA `GetEndpoints` (`HEL`/`OPN` read-only endpoint discovery), and BACnet `Who-Is` (unconfirmed service `0x08`). Blocked unless explicitly enabled at both the site/agent level (`ot_probes_enabled: True`) and device level (`ot_probe_enabled` / `ot_probes`), enforcing a per-device minimum interval (`ot_probe_min_interval_s`, default 300s).

---

## Task 1: Industrial OUI Database & MAC Collector / History Integration

**Files:**
- Create: `collectors/industrial_oui.py`
- Modify: `collectors/mac_collector.py`
- Modify: `collectors/mac_history.py`
- Create: `tests/test_industrial_oui.py`

### Steps
1. Create `collectors/industrial_oui.py` with IEEE OUI prefixes (`aa:bb:cc` normalized lowercase) for:
   - `Siemens`
   - `Rockwell/Allen-Bradley`
   - `Schneider Electric` <!-- check-private-data: ok -->
   - `Beckhoff`
   - `Omron`
   - `Moxa`
   - `Hirschmann`
   - `Phoenix Contact`
   - `Wago`
   - `Fanuc`
   - `ABB`
   Provide `lookup_industrial_oui(mac: Optional[str]) -> str` and `is_industrial_oui(mac: Optional[str]) -> bool`.
2. In `collectors/mac_collector.py`, enrich normalized rows in `_row_from()`, `parse_matm_oper()`, and ` parse_cli_mac_table()` (or centrally in `mark_uplinks` / `collect_mac_table` / `collect_wlc`) with `oui_vendor` when not already set and when `lookup_industrial_oui(mac)` matches.
3. In `collectors/mac_history.py`:
   - In `record_sightings()`, if `r.get("oui_vendor")` is empty, fall back to `lookup_industrial_oui(mac)`.
   - In `endpoint_inventory()`, resolve `oui_vendor` from sighting rows or `lookup_industrial_oui(mac)`, and add `"OT"` to `flags` when the MAC belongs to an industrial OUI vendor (or `industrial_vendor` is matched).
4. Write unit tests in `tests/test_industrial_oui.py` covering all 11 vendors, MAC format normalization (`AA-BB-CC...`, `aabb.ccdd.eeff`, `aa:bb:cc...`), non-industrial MACs returning `""`, preservation of explicit `oui_vendor` in `record_sightings`, and `endpoint_inventory` enrichment.

---

## Task 2: Passive OT Protocol Tagging in Observability Ingesters

**Files:**
- Create: `observability/ingesters/ot_protocols.py`
- Modify: `observability/ingesters/syslog.py`
- Modify: `observability/fieldmap.py`
- Modify: `observability/normalize.py`
- Create: `tests/test_ot_passive_protocols.py`

### Steps
1. Create `observability/ingesters/ot_protocols.py` defining the 8 OT protocols:
   - `modbus_tcp` (`Modbus TCP`, TCP port 502)
   - `s7comm` (`S7comm`, TCP port 102)
   - `ethernet_ip` (`EtherNet/IP`, TCP port 44818, UDP port 2222)
   - `opc_ua` (`OPC-UA`, TCP port 4840)
   - `profinet` (`PROFINET`, UDP ports 34962, 34963, 34964, EtherType `0x8892`)
   - `bacnet` (`BACnet`, UDP port 47808)
   - `iec_104` (`IEC 60870-5-104`, TCP port 2404)
   - `dnp3` (`DNP3`, TCP/UDP port 20000)
   Provide:
   - `identify_ot_protocol(protocol: Optional[str] = None, src_port: Optional[int] = None, dst_port: Optional[int] = None, message: Optional[str] = None, ethertype: Optional[int] = None) -> Optional[dict]` returning `{"id": ..., "name": ..., "transport": ..., "port": ...}`
   - `tag_record(record: dict) -> dict` for passive flow/syslog/mirror metadata records.
2. Integrate `identify_ot_protocol` into `observability/fieldmap.py` (`extract()` returns `ot_protocol` id when matched from port/transport/service/message keywords) and `observability/ingesters/syslog.py` (`_parse()` attaches `ot_protocol` when passively detected).
3. In `observability/normalize.py`, include `ot_protocol` in `_syslog_attrs()` when present so normalized `events` carry `attrs_json.ot_protocol` without altering the SQLite schema or breaking existing event consumers.
4. Write unit tests in `tests/test_ot_passive_protocols.py` testing all 8 protocols across TCP/UDP port pairs, reverse source-port replies, EtherType/mirror metadata, FortiGate/Palo Alto/generic syslog lines, and `normalize._from_syslog` projection.

---

## Task 3: Opt-In Rate-Limited Read-Only OT Probes in `services/probe_agent.py`

**Files:**
- Modify: `services/probe_agent.py`
- Create: `tests/test_ot_probe_agent.py`

### Steps
1. Implement read-only packet builders, response parsers, and a guard against write function codes in `services/probe_agent.py`:
   - `ethernet_ip` (`ListIdentity`, command `0x0063` over TCP/UDP 44818): extracts vendor ID, device type, product code, revision, serial number, and product name.
   - `modbus` (FC 43 / MEI 14 `Read Device Identification`, MBAP + `0x2B 0x0E 0x01 0x00` over TCP 502): extracts VendorName (object 0x00), ProductCode (object 0x01), MajorMinorRevision (object 0x02). Explicitly assert that only FC `0x2B` / MEI `0x0E` is ever constructed.
   - `opc_ua` (`GetEndpoints` / `HEL` handshake over TCP 4840): sends read-only OPC-UA `HEL` frame (`b"HEL" + b"F" + ...`) and parses `ACK` / server endpoint metadata.
   - `bacnet` (`Who-Is` / unicast identity inquiry over UDP 47808, BVLC `0x81 0x0a 0x00 0x08 0x01 0x00 0x10 0x08` and `I-Am` response parser `0x10 0x00` extracting vendor ID / device instance).
2. Enforce strict opt-in and rate-limiting gates on `Agent`:
   - Default `ot_probes_enabled: False` and `ot_probe_min_interval_s: 300` in `load_config()` and `Agent.__init__()`.
   - `run_ot_probe(device, protocol, timeout=2.0)` refuses with `PermissionError` (or `{"status": "blocked", ...}`) unless **both** site config `self.cfg.get("ot_probes_enabled") is True` **and** device explicitly opts in (`device.get("ot_probe_enabled") is True` or `protocol` in `device.get("ot_probes", [])`).
   - Per-`(device_ip, protocol)` rate limiter (`self._ot_probe_last_ts`) blocks probes requested within `ot_probe_min_interval_s` (minimum floor 10s, default 300s) with `{"status": "rate_limited", ...}`.
   - Support `_agent_ot_probe` RPC / `kind == "ot_probe"` job handling in `Agent.run_jobs()` and `maybe_run_ot_probes(devices)` in `Agent.cycle()` (which is a no-op unless `ot_probes_enabled` is True).
3. Write comprehensive unit tests in `tests/test_ot_probe_agent.py` verifying:
   - Blocked when site `ot_probes_enabled` is False (even if device opts in).
   - Blocked when device does not explicitly opt in (even if site `ot_probes_enabled` is True).
   - Rate-limited when called twice within `ot_probe_min_interval_s`.
   - Frame construction and response parsing for all 4 protocols (`ethernet_ip`, `modbus`, `opc_ua`, `bacnet`) using mocked sockets (no real network traffic).
   - Modbus frame verification ensuring function code is strictly `0x2B` (43) / MEI `0x0E` (14) and never a coil/register write (`0x05`, `0x06`, `0x0F`, `0x10`).

---

## Task 4: Full Verification Gate

**Steps:**
1. `uv run pyrefly check`
2. `uv run python scripts/check_frontend.py`
3. `uv run pytest tests -n 4`
4. `uv run python scripts/check_no_private_data.py`
5. `uv run graphify update .`
