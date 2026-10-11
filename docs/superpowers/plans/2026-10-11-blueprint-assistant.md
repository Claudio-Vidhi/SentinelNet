# Blueprint Assistant — Implementation Plan (sub-project 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill an organization's Blueprint draft from three sources — the operator's text («Descrivi la rete», through the active AI profile), the configuration backups («Ricava dalle configurazioni», deterministic, optional AI pass for names and roles) and external MCP clients (`blueprint_propose`) — without any of them ever applying the draft.

**Architecture:** Every output is a list of draft operations appended with `blueprint.add_ops(org, ops, "assistant", by)`, which already validates them with `blueprint_model.apply_ops`. `services/blueprint_derive.py` is pure (`(view, devices, analyses) -> (ops, notes)`); `services/blueprint_assistant.py` holds the LLM conversation (`describe`), the backup gathering plus optional AI pass (`derive`) and the per-organization instructions; `routers/blueprint.py` gains four routes. The MCP side adds one permission, `bp_draft`, to read-only grants: the session JWT carries `bpd` next to `ro`, and only `POST /api/blueprint/{org}/assistant-draft` reads it. The UI adds an «Assistente» modal and an «Istruzioni assistente» modal to the Blueprint tab, and a checkbox to the MCP consent page.

**Tech Stack:** Python 3 / FastAPI / sqlite3 (stdlib) / classic-script JS / unittest via pytest (`uv run pytest tests -n 4`).

**Spec:** `docs/superpowers/specs/2026-10-11-blueprint-assistant-design.md` (builds on `docs/superpowers/specs/2026-10-11-network-blueprint-design.md` and its plan `docs/superpowers/plans/2026-10-11-network-blueprint.md`).

## Global Constraints

- Every assistant output goes through `blueprint.add_ops(org, ops, "assistant", by)`. Nothing in this plan calls `blueprint.apply`, `replace_ops`, `restore`, `preset`, `discard` or `align`.
- LLM calls only through `routers.ai.chat_with_active_profile(messages) -> (reply, profile)`, imported inside the function (`from routers.ai import chat_with_active_profile`) so tests can patch `routers.ai.chat_with_active_profile`. Tests never reach a real provider.
- Text limit for the description and the instructions: 4000 characters (`blueprint_assistant.MAX_TEXT`).
- `organizations.assistant_instructions TEXT NOT NULL DEFAULT ''`, ALTERed into old databases like `locations.gateway`; not part of revisions.
- MCP: `bpd` is **added** to a read-only session next to `ro`, never instead of it (memory rule: read-only grants are never re-minted without `ro`). `bp_draft` is stored only when the grant is read-only and the approving user is an admin.
- `assistant-draft` admits an admin session, or an `ro` + `bpd` session whose user is an admin **on disk at call time**; source forced to `assistant`.
- API: every new route `require_tab("tab-blueprint")` + `_org(org, user)` (tenant + existence). Errors: `ValueError`/`OpError` → 422 `{"message", "index"}`; AI errors keep `chat_with_active_profile`'s own codes (400 no profile / no key, 429 rate limit, 502 provider).
- New comments in English; Italian user/audit strings like the existing ones; LLM prompts in English; UI strings via `tr()` in both languages; `openModal`/`closeModal`; accessible names; no inline handlers.
- Example data only: `acme`, `beta`, `milano`, `roma`, `torino`, `10.x`, `192.0.2.x`, `198.51.100.x`, `203.0.113.x`; synthetic IOS/FortiOS snippets.
- Gate before each commit: `uv run pyrefly check`, `uv run pytest tests -n 4`, `uv run python scripts/check_no_private_data.py`; tasks touching `static/js` or `templates/` also `uv run python scripts/check_frontend.py`, `uv run python scripts/check_i18n_coverage.py --strict`, `uv run python scripts/check_a11y.py --strict`; `graphify update .` after code changes (last task).
- Known noise: `tests/test_observability_ingest.py::test_load_5kpps_loop_latency` can fail under `-n 4` on a busy machine — re-run it alone (`uv run pytest tests/test_observability_ingest.py -k load_5kpps`) before treating it as a regression.
- `tests/test_router_parity.py` holds allow-lists: `/api/blueprint` is already in `ALLOWED_NEW_PREFIXES` and `NEW_PREFIXES`; every **new Pydantic schema** must be appended to `NEW_SCHEMAS` (Tasks 5 and 6 say where).
- `tests/test_lazy_tab_scripts.py` / `tests/test_i18n_keys.py` reject computed keys like `tr('prefix_' + x)`: use literal `tr('key')` (or the existing `trEnum` helper in `blueprint.js` for enum values that already have every entry).

## Spec adjustments (made while planning, written back into the spec in Task 1)

1. **AI error codes.** `chat_with_active_profile` already raises `HTTPException` 400 («Nessun profilo AI configurato/attivo…», also for a missing API key), 429 (rate limit) and 502 (`AiAssistantError`). The assistant reuses it unchanged instead of answering 503: the AI tab and the classification assistant already return these codes, and wrapping them would mean a second error vocabulary for the same failure.
2. **`config_analyzer` FortiOS output.** `vpn.phase1` stays the list of names (`tests/test_config_analyzer_multivendor.py` and the analyzer UI read it so); a new `vpn.peers` holds one `{"name", "remote_gw"}` per phase 1 (`remote_gw` `''` for dial-up).
3. **VPN match.** A FortiGate's `remote-gw` is normally the other side's WAN address, rarely its management IP. A peer matches a device when `remote-gw` is the device's inventory IP **or** any interface address in that device's backup.
4. **`add_subnet` details.** Interfaces administratively down (IOS `shutdown`, FortiOS `status down`) are skipped; a network that **overlaps** a location subnet counts as covered; a network seen in two locations goes to the first one by location id. Only IPv4.
5. **`set_gateway` details.** Default routes inside a VRF (IOS `ip route vrf Mgmt-vrf 0.0.0.0 0.0.0.0 …`, common on Catalyst management ports) do not count; more than one candidate yields a note, no op.
6. **Routes.** The spec names the functions, not their paths: `POST /api/blueprint/{org}/assistant/describe` `{text}` and `POST /api/blueprint/{org}/assistant/derive` `{use_ai}` (admin).
7. **Retry message index.** `apply_ops` numbers operations across the whole draft; the retry message numbers them within the LLM's reply («operazione 1» is the reply's first op even when the draft already holds two). `OpError` gains `.reason` (the message without the «Modifica N:» prefix) for this.
8. **`bpd` re-checked per request.** Besides the session-time check, `assistant-draft` re-reads the user's role from disk at every call: a user demoted after the session opened is refused at once (a JWT outlives a role change).

## Review Focus

1. **LLM answer whose `ops` holds a non-object (a string, `null`) or is not a list** → one retry, then 422 with a readable message; never a 500 (`dict(o, source=…)` in `add_ops` would raise `TypeError` on an int). Test in Task 4 (`test_non_object_ops_are_retried_then_422`).
2. **Describe on a draft that already holds operations** → the retry message names the failing op by its position in the LLM's reply («operazione 1»), not in the whole draft. Test in Task 4 (`test_error_index_counts_only_the_reply`).
3. **«Ricava» on an organization whose draft already adds a subnet** → the same network is not proposed again (derive reads the preview). Tests in Task 3 (`test_covered_networks_are_not_proposed_again`) and Task 4 (`test_reads_the_preview`).
4. **Renaming or creating an organization after its instructions were saved** → instructions survive (`write_orgs` upserts only `name`/`description`). Test in Task 1 (`test_survive_every_org_write`).
5. **A read-only MCP session with `bpd`** → can append through `assistant-draft` only: `POST /draft` and `/draft/apply` stay 403, and the right disappears when the user is demoted. Test in Task 6 (`test_read_only_grant_with_bp_draft_appends_and_nothing_else`, `test_demoted_user_loses_it_at_once`).

---

## File map

| File | Change |
|---|---|
| `services/inventory_store.py` | `organizations.assistant_instructions` (+ ALTER), `read_instructions`, `write_instructions` |
| `ai/config_analyzer.py` | FortiOS `vpn.peers` |
| `services/blueprint_derive.py` (new) | pure `derive(view, devices, analyses) -> (ops, notes)` |
| `services/blueprint_model.py` | `OpError.reason` |
| `services/blueprint.py` | `state()` gains `instructions`, `ai_available`; `_ai_available()` |
| `services/blueprint_assistant.py` (new) | `MAX_TEXT`, `describe`, `derive`, `set_instructions` |
| `routers/blueprint.py` | `/assistant/describe`, `/assistant/derive`, `PUT /instructions`, `/assistant-draft` + `_drafter` |
| `security/mcp_grants.py`, `routers/mcp.py` | `bp_draft` on grants, `can_bp_draft` on consent info, `bpd` claim |
| `templates/mcp_authorize.html`, `static/js/mcp-authorize.js` | consent checkbox |
| `ai/mcp_server.py` | tools `blueprint_get`, `blueprint_propose` |
| `templates/dashboard.html`, `static/js/blueprint.js`, `static/js/i18n.js`, `static/css/dashboard.css` | «Assistente» and «Istruzioni assistente» buttons + modals, source tag in the draft review |
| Tests | `test_blueprint_schema.py` (+class), `test_config_analyzer_multivendor.py` (+class), `test_blueprint_derive.py`, `test_blueprint_assistant.py`, `test_blueprint_assistant_api.py`, `test_mcp_server_tools.py` (+class), `test_blueprint_tab.py` (+class), `test_router_parity.py` (allow-list) |
| Docs | spec adjustments, `docs/network-blueprint.md` (Assistant section), `docs/hardening.md` (§7 tiers), `README.md` (MCP consent paragraph), `docs/README.md` (index row) |

---

### Task 1: Organization instructions storage + spec adjustments

**Model:** sonnet

**Files:**
- Modify: `services/inventory_store.py` (`_SCHEMA` organizations line ~36, `connect` ~79, new functions after `write_orgs` ~146)
- Modify: `docs/superpowers/specs/2026-10-11-blueprint-assistant-design.md`
- Test: `tests/test_blueprint_schema.py` (append a class)

**Interfaces:**
- Produces:
  - `inventory_store.read_instructions(conn, org: str) -> str` (`''` for an unknown org or none saved)
  - `inventory_store.write_instructions(conn, org: str, text: str) -> None` (own transaction)
  - `read_orgs`/`write_orgs` unchanged: the upsert sets only `name`, `description`, so the column survives every organization write.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_blueprint_schema.py`:

```python
class TestAssistantInstructions(_Base):
    def test_round_trip(self):
        self.assertEqual(inventory_store.read_instructions(self.conn, "acme"), "")
        inventory_store.write_instructions(self.conn, "acme", "Sedi: nome della città.")
        self.assertEqual(inventory_store.read_instructions(self.conn, "acme"), "Sedi: nome della città.")
        self.assertEqual(inventory_store.read_instructions(self.conn, "nobody"), "")

    def test_survive_every_org_write(self):
        inventory_store.write_instructions(self.conn, "acme", "Sedi: nome della città.")
        orgs = inventory_store.read_orgs(self.conn)
        orgs["acme"]["name"] = "ACME S.p.A."          # what a rename writes
        orgs["beta"] = {"description": ""}             # what a create writes
        inventory_store.write_orgs(self.conn, orgs)
        self.assertEqual(inventory_store.read_instructions(self.conn, "acme"), "Sedi: nome della città.")
        self.assertNotIn("assistant_instructions", inventory_store.read_orgs(self.conn)["acme"])

    def test_database_from_before_gets_the_column(self):
        path = os.path.join(tempfile.mkdtemp(prefix="bp_old_org_"), "inventory.db")
        raw = sqlite3.connect(path)
        raw.executescript(
            "CREATE TABLE organizations (key TEXT PRIMARY KEY, name TEXT, description TEXT NOT NULL DEFAULT '');"
            "INSERT INTO organizations VALUES ('acme', NULL, '');")
        raw.commit()
        raw.close()
        conn = inventory_store.connect(path)
        self.addCleanup(conn.close)
        self.assertEqual(inventory_store.read_instructions(conn, "acme"), "")
        inventory_store.write_instructions(conn, "acme", "x")
        self.assertEqual(inventory_store.read_instructions(conn, "acme"), "x")


class TestInstructionsThroughTheManager(unittest.TestCase):
    def test_rename_through_update_group_keeps_them(self):
        from unittest.mock import patch
        from services import inventory_manager
        tmp = tempfile.mkdtemp(prefix="bp_instr_mgr_")
        p = patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv"))
        p.start()
        self.addCleanup(p.stop)
        inventory_manager.save_groups({"acme": {"description": ""}})
        with inventory_manager._db() as conn:
            inventory_store.write_instructions(conn, "acme", "Ruoli: hq solo Milano.")
        self.assertTrue(inventory_manager.update_group("acme", "ACME", "cliente"))
        with inventory_manager._db() as conn:
            self.assertEqual(inventory_store.read_instructions(conn, "acme"), "Ruoli: hq solo Milano.")
```

(`os`, `sqlite3`, `tempfile`, `unittest`, `inventory_store` and `_Base` are already imported/defined in that file.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_schema.py -v`
Expected: FAIL — `AttributeError: module 'services.inventory_store' has no attribute 'read_instructions'`.

- [ ] **Step 3: Implement** — `services/inventory_store.py`.

Replace the organizations line of `_SCHEMA`:

```python
    "CREATE TABLE IF NOT EXISTS organizations (key TEXT PRIMARY KEY, name TEXT, "
    "description TEXT NOT NULL DEFAULT '', assistant_instructions TEXT NOT NULL DEFAULT '');",
```

In `connect`, right after the `locations.gateway` ALTER:

```python
            # Same for the Blueprint assistant's per-organization instructions
            # (spec 2026-10-11 blueprint-assistant).
            if "assistant_instructions" not in {r["name"] for r in conn.execute("PRAGMA table_info(organizations)")}:
                conn.execute("ALTER TABLE organizations ADD COLUMN assistant_instructions TEXT NOT NULL DEFAULT ''")
```

After `write_orgs`:

```python
# Not in read_orgs/write_orgs on purpose: write_orgs upserts only name and
# description, so every organization write (create, rename) keeps them.
def read_instructions(conn, org: str) -> str:
    r = conn.execute("SELECT assistant_instructions FROM organizations WHERE key = ?", (org,)).fetchone()
    return r[0] if r else ""


def write_instructions(conn, org: str, text: str) -> None:
    with conn:
        conn.execute("UPDATE organizations SET assistant_instructions = ? WHERE key = ?", (text, org))
```

- [ ] **Step 4: Write the spec adjustments** — in `docs/superpowers/specs/2026-10-11-blueprint-assistant-design.md`, make these edits (text to replace → replacement):

  - In «Ricava», bullet `add_subnet`: after `One op per (location, network).` add ` Interfaces administratively down are skipped; a network that overlaps a location subnet counts as covered; a network seen in two locations goes to the first location by id. IPv4 only.`
  - Bullet `set_gateway`: `static default route (\`0.0.0.0/0\`) in its backup → that device.` → `static default route (\`0.0.0.0/0\`, outside any VRF) in its backup → that device; more than one candidate → a note, no op.`
  - Bullet `add_link vpn`: `whose \`remote-gw\` is the IP of a device in another location` → `whose \`remote-gw\` is the inventory IP, or an interface address in the backup, of a device in another location`.
  - Same bullet: `it gains \`{"name", "remote_gw"}\` per phase 1 (FortiOS only).` → `it gains \`vpn.peers\`, one \`{"name", "remote_gw"}\` per phase 1 (FortiOS only); \`vpn.phase1\` stays the list of names its readers expect.`
  - In «Descrivi la rete», bullet Parse: `(operation index and message)` → `(operation index within the reply, and message)`.
  - At the end of «Descrivi la rete» add the bullet `- Route: \`POST /api/blueprint/{org}/assistant/describe\` \`{text}\` (admin).`; at the end of «Ricava» add `- Route: \`POST /api/blueprint/{org}/assistant/derive\` \`{use_ai}\` (admin).`
  - In «MCP», after the `/api/mcp/session` bullet add `- \`assistant-draft\` re-reads the user's role at every call: a user demoted after the session opened is refused at once.`
  - In «Errors and privacy», replace the first bullet with: `- No active AI profile (or no API key) → 400, provider errors → 502 with the \`AiAssistantError\` message, rate limit → 429: the codes \`routers/ai.chat_with_active_profile\` already returns to the AI tab and the classification assistant. For derive, the AI pass is just skipped.`

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/test_blueprint_schema.py tests/test_inventory_store.py tests/test_location_manager.py -v`
Expected: PASS.

- [ ] **Step 6: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add services/inventory_store.py tests/test_blueprint_schema.py docs/superpowers/specs/2026-10-11-blueprint-assistant-design.md
git commit -m "feat(blueprint): per-organization assistant instructions in inventory.db"
```

---

### Task 2: FortiOS phase-1 peers in `config_analyzer`

**Model:** sonnet

**Files:**
- Modify: `ai/config_analyzer.py` (`analyze_fortios_config`, the «IPsec VPN» block ~line 727 and the return dict ~line 809)
- Test: `tests/test_config_analyzer_multivendor.py` (append a class)

**Interfaces:**
- Produces: `analyze_fortios_config(content)["vpn"]["peers"] -> list[{"name": str, "remote_gw": str}]`, one per phase 1 in definition order (`remote_gw` `''` when unset). `vpn.phase1` / `vpn.phase2` unchanged. IOS keeps `vpn` as a list (no `peers`).

- [ ] **Step 1: Write the failing test** — append to `tests/test_config_analyzer_multivendor.py`, before the `if __name__` block if there is one:

```python
class TestFortiosPhase1Peers(unittest.TestCase):
    """Blueprint assistant (spec 2026-10-11): the peer of each phase 1."""

    CFG = ('config vpn ipsec phase1-interface\n'
           '    edit "to-roma"\n'
           '        set interface "wan1"\n'
           '        set remote-gw 198.51.100.2\n'
           '    next\n'
           '    edit "dialup"\n'
           '        set type dynamic\n'
           '    next\n'
           'end\n')

    def test_remote_gw_per_phase1(self):
        r = ca.analyze_fortios_config(self.CFG)
        self.assertEqual(r["vpn"]["peers"], [{"name": "to-roma", "remote_gw": "198.51.100.2"},
                                             {"name": "dialup", "remote_gw": ""}])
        self.assertEqual(r["vpn"]["phase1"], ["to-roma", "dialup"])
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_config_analyzer_multivendor.py -k Phase1Peers -v`
Expected: FAIL — `KeyError: 'peers'`.

- [ ] **Step 3: Implement** — in `analyze_fortios_config` replace the phase-1 loop:

```python
    # --- IPsec VPN (phase 1 / phase 2 names; phase-1 peers) ---
    phase1 = []
    phase2 = []
    # The peer of each phase 1, for the Blueprint assistant (spec 2026-10-11
    # blueprint-assistant); phase1 stays the list of names its readers expect.
    peers = []
    for sec in ('vpn ipsec phase1-interface', 'vpn ipsec phase1'):
        node = _forti_get(root, sec)
        if node:
            phase1.extend(node["children"].keys())
            peers.extend({"name": name, "remote_gw": _forti_set1(n, 'remote-gw')}
                         for name, n in node["children"].items())
```

and in the return dict:

```python
        "vpn": {"phase1": phase1, "phase2": phase2, "peers": peers},
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_config_analyzer_multivendor.py tests/test_config_analyzer_fortigate.py -v`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add ai/config_analyzer.py tests/test_config_analyzer_multivendor.py
git commit -m "feat(config-analyzer): FortiOS phase-1 peers (remote-gw)"
```

---

### Task 3: `blueprint_derive` — operations from the backups (pure)

**Model:** opus

**Files:**
- Create: `services/blueprint_derive.py`
- Test: `tests/test_blueprint_derive.py`

**Interfaces:**
- Consumes: `blueprint_model.link_id(a, b, kind)`; analyses as `config_analyzer.analyze_config` / `analyze_fortios_config` / `analyze_device` return them — `interfaces[]` with `name`, `ip` (`"a.b.c.d/nn"` or `''`), IOS `shutdown: bool`, FortiOS `status: "up"|"down"`; `routing.static[]` with `prefix` (`"0.0.0.0/0"` for a default) and IOS `vrf`; FortiOS `vpn` dict with `peers` (Task 2), IOS `vpn` list.
- Produces: `blueprint_derive.derive(view: dict, devices: list, analyses: dict) -> tuple[list, list]`
  - `view`: `{"locations": {id: loc}, "links": {id: link}}` (the preview when a draft exists)
  - `devices`: inventory rows of the organization (`"IP"`, `"Location"`)
  - `analyses`: `{ip: dict | None}` — `None`/missing = no backup; a dict without `"interfaces"` = unreadable backup
  - returns `(ops, notes)`: ops in the order add_subnet…, set_gateway…, add_link…; notes are Italian sentences.

- [ ] **Step 1: Write the failing tests** — `tests/test_blueprint_derive.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""«Ricava dalle configurazioni»: draft operations from config backups (pure)."""
import unittest

from ai import config_analyzer as ca
from services.blueprint_derive import derive

IOS = """hostname switch-01
!
interface Vlan10
 ip address 10.10.1.1 255.255.255.0
!
interface Vlan20
 ip address 10.10.2.1 255.255.255.0
 shutdown
!
interface Vlan30
 ip address 10.10.3.1 255.255.255.0
!
interface Loopback0
 ip address 10.255.0.1 255.255.255.255
!
interface Loopback1
 ip address 10.10.4.1 255.255.255.0
!
interface GigabitEthernet0/1
 ip address 203.0.113.6 255.255.255.252
!
interface GigabitEthernet0/2
 ip address 10.10.9.0 255.255.255.254
!
interface GigabitEthernet0/3
 ip address 192.0.2.1 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 203.0.113.5
ip route vrf Mgmt-vrf 0.0.0.0 0.0.0.0 10.10.0.254
"""

FGT = """config system interface
    edit "wan1"
        set ip 203.0.113.10 255.255.255.252
    next
    edit "internal"
        set ip 10.20.1.1 255.255.255.0
    next
    edit "dmz"
        set ip 10.20.2.1 255.255.255.0
        set status down
    next
end
config router static
    edit 1
        set gateway 203.0.113.9
        set device "wan1"
    next
end
config vpn ipsec phase1-interface
    edit "to-milano"
        set interface "wan1"
        set remote-gw 203.0.113.6
    next
    edit "to-partner"
        set interface "wan1"
        set remote-gw 198.51.100.77
    next
end
"""


def loc(name, role="branch", subnets=(), gateway=""):
    return {"org": "acme", "name": name, "role": role, "subnets": list(subnets), "probe": "central", "gateway": gateway}


LOCS = {"milano": loc("Milano", "hq", ["10.10.1.0/24"]), "roma": loc("Roma"), "torino": loc("Torino")}
VIEW = {"locations": LOCS, "links": {}}


def dev(ip, location):
    return {"IP": ip, "Group": "acme", "Location": location}


def an(ifaces=(), default=False, peers=()):
    return {"interfaces": [{"name": n, "ip": ip} for n, ip in ifaces],
            "routing": {"static": [{"prefix": "0.0.0.0/0", "vrf": ""}] if default else []},
            "vpn": {"phase1": [n for n, _ in peers], "phase2": [],
                    "peers": [{"name": n, "remote_gw": gw} for n, gw in peers]}}


class TestFromRealParsers(unittest.TestCase):
    def test_ios_switch_and_fortigate(self):
        devices = [dev("10.20.0.1", "roma"), dev("10.10.0.1", "milano")]
        analyses = {"10.10.0.1": ca.analyze_config(IOS), "10.20.0.1": ca.analyze_fortios_config(FGT)}
        ops, notes = derive(VIEW, devices, analyses)
        self.assertEqual(ops, [
            # Vlan10 covered, Vlan20 shut, loopbacks, /31, public 203.0.113.x and 192.0.2.x skipped
            {"op": "add_subnet", "id": "milano", "subnet": "10.10.3.0/24"},
            {"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"},          # dmz is down
            {"op": "set_gateway", "id": "milano", "ip": "10.10.0.1"},            # the VRF default does not count
            {"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"},
            # remote-gw 203.0.113.6 is the switch's Gi0/1 address
            {"op": "add_link", "a": "roma", "b": "milano", "kind": "vpn", "note": "to-milano"},
        ])
        self.assertEqual(notes, ["1 peer IPsec verso indirizzi che non sono apparati di questa organizzazione."])


class TestSubnets(unittest.TestCase):
    def test_covered_networks_are_not_proposed_again(self):
        # The preview already holds 10.20.0.0/16 (e.g. from the open draft).
        view = {"locations": dict(LOCS, roma=loc("Roma", subnets=["10.20.0.0/16"])), "links": {}}
        ops, _ = derive(view, [dev("10.20.0.1", "roma")], {"10.20.0.1": an([("internal", "10.20.1.1/24")])})
        self.assertEqual(ops, [])

    def test_same_network_in_two_locations_goes_to_the_first(self):
        same = an([("lan", "10.40.0.1/24")])
        ops, _ = derive(VIEW, [dev("10.30.0.1", "torino"), dev("10.20.0.1", "roma")],
                        {"10.30.0.1": same, "10.20.0.1": same})
        self.assertEqual(ops, [{"op": "add_subnet", "id": "roma", "subnet": "10.40.0.0/24"}])

    def test_unparsable_interface_addresses_are_ignored(self):
        ops, _ = derive(VIEW, [dev("10.20.0.1", "roma")],
                        {"10.20.0.1": an([("a", ""), ("b", "10.20.0.1 255.0.0.0"), ("c", "fe80::1/64")])})
        self.assertEqual(ops, [])


class TestGateways(unittest.TestCase):
    def test_exactly_one_candidate(self):
        two = derive(VIEW, [dev("10.20.0.1", "roma"), dev("10.20.0.2", "roma")],
                     {"10.20.0.1": an(default=True), "10.20.0.2": an(default=True)})
        self.assertEqual(two, ([], ["Roma: 2 apparati con rotta di default, gateway da scegliere a mano."]))

    def test_location_with_a_gateway_or_only_a_vrf_default(self):
        has_gw = {"locations": dict(LOCS, roma=loc("Roma", gateway="10.20.0.9")), "links": {}}
        self.assertEqual(derive(has_gw, [dev("10.20.0.1", "roma")], {"10.20.0.1": an(default=True)}), ([], []))
        vrf_only = {"interfaces": [], "routing": {"static": [{"prefix": "0.0.0.0/0", "vrf": "Mgmt-vrf"}]}, "vpn": []}
        self.assertEqual(derive(VIEW, [dev("10.20.0.1", "roma")], {"10.20.0.1": vrf_only}), ([], []))


class TestVpnLinks(unittest.TestCase):
    DEVICES = [dev("10.10.0.1", "milano"), dev("10.20.0.1", "roma"), dev("10.20.0.2", "roma")]
    ANALYSES = {"10.10.0.1": an(peers=[("to-roma", "10.20.0.1"), ("to-self", "10.10.0.1")]),
                "10.20.0.1": an(peers=[("to-milano", "10.10.0.1")]),
                "10.20.0.2": an(peers=[("to-roma-2", "10.20.0.1")])}

    def test_one_link_per_pair_by_management_ip(self):
        ops, notes = derive(VIEW, self.DEVICES, self.ANALYSES)
        self.assertEqual(ops, [{"op": "add_link", "a": "milano", "b": "roma", "kind": "vpn", "note": "to-roma"}])
        self.assertEqual(notes, [])

    def test_existing_vpn_link_is_not_proposed(self):
        linked = {"locations": LOCS, "links": {"milano--roma--vpn": {
            "org": "acme", "a": "milano", "b": "roma", "kind": "vpn", "note": ""}}}
        self.assertEqual(derive(linked, self.DEVICES, self.ANALYSES)[0], [])


class TestSkippedDevices(unittest.TestCase):
    def test_counted_in_the_notes(self):
        devices = [dev("10.30.0.1", ""), dev("10.30.0.2", "nowhere"), dev("10.20.0.1", "roma"), dev("10.20.0.2", "roma")]
        ops, notes = derive(VIEW, devices, {"10.20.0.1": None, "10.20.0.2": {}})
        self.assertEqual(ops, [])
        self.assertEqual(notes, ["2 apparati senza sede: ignorati.",
                                 "1 apparati senza backup della configurazione.",
                                 "1 backup non leggibili."])
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_derive.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'services.blueprint_derive'`.

- [ ] **Step 3: Implement** — `services/blueprint_derive.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""«Ricava dalle configurazioni» (spec 2026-10-11 blueprint-assistant): draft
operations read from the configuration backups of an organization's devices.
Pure: the caller passes the model view (the preview when a draft exists), the
inventory rows and one config_analyzer analysis per device IP."""
import ipaddress

from services.blueprint_model import link_id

_RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _addresses(analysis: dict):
    """(interface, IPv4Interface) for every parsable IPv4 interface address."""
    for i in analysis.get("interfaces") or []:
        try:
            addr = ipaddress.ip_interface(i.get("ip") or "")
        except ValueError:
            continue
        if addr.version == 4:
            yield i, addr


def _lan(i: dict, addr) -> bool:
    """An interface whose network may be a location subnet."""
    net = addr.network
    return not (net.prefixlen >= 31 or addr.is_loopback
                or str(i.get("name") or "").lower().startswith("loopback")
                or i.get("shutdown") or i.get("status") == "down"
                or not any(net.subnet_of(r) for r in _RFC1918))


def derive(view: dict, devices: list, analyses: dict):
    """Returns (ops, notes): add_subnet, set_gateway and add_link vpn
    operations, then one Italian note per kind of skipped input."""
    locs, links = view["locations"], view["links"]
    taken = [n for n in (ipaddress.ip_network(s, strict=False)
                         for l in locs.values() for s in l.get("subnets") or []) if n.version == 4]
    no_loc = no_backup = unreadable = unknown = 0
    placed, owner = [], {}          # owner: address -> location of the device holding it
    for d in sorted(devices, key=lambda d: (d.get("Location") or "", d.get("IP") or "")):
        lid, ip = d.get("Location") or "", d.get("IP") or ""
        if lid not in locs:
            no_loc += 1
            continue
        owner.setdefault(ip, lid)
        a = analyses.get(ip)
        if a is None:
            no_backup += 1
        elif "interfaces" not in a:
            unreadable += 1
        else:
            placed.append((lid, ip, a))
            for _i, addr in _addresses(a):
                owner.setdefault(str(addr.ip), lid)

    ops = []
    for lid, _ip, a in placed:
        for i, addr in _addresses(a):
            net = addr.network
            if not _lan(i, addr) or any(net.overlaps(t) for t in taken):
                continue
            taken.append(net)            # one op per network: the first location keeps it
            ops.append({"op": "add_subnet", "id": lid, "subnet": str(net)})

    # A default route inside a VRF is a management port's, not the location's exit.
    defaults: dict = {}
    for lid, ip, a in placed:
        if any(r.get("prefix") == "0.0.0.0/0" and not r.get("vrf")
               for r in (a.get("routing") or {}).get("static") or []):
            defaults.setdefault(lid, []).append(ip)
    crowded = []
    for lid in sorted(defaults):
        if locs[lid].get("gateway"):
            continue
        if len(defaults[lid]) == 1:
            ops.append({"op": "set_gateway", "id": lid, "ip": defaults[lid][0]})
        else:
            crowded.append(f"{locs[lid]['name']}: {len(defaults[lid])} apparati con rotta di default, "
                           "gateway da scegliere a mano.")

    proposed = set()
    for lid, _ip, a in placed:
        vpn = a.get("vpn")
        for p in (vpn.get("peers") or []) if isinstance(vpn, dict) else []:
            gw = p.get("remote_gw") or ""
            if not gw:
                continue                 # dial-up phase 1: no fixed peer
            other = owner.get(gw)
            if other is None:
                unknown += 1
                continue
            k = link_id(lid, other, "vpn")
            if other == lid or k in links or k in proposed:
                continue
            proposed.add(k)
            ops.append({"op": "add_link", "a": lid, "b": other, "kind": "vpn", "note": p.get("name") or ""})

    notes = [text for n, text in ((no_loc, f"{no_loc} apparati senza sede: ignorati."),
                                  (no_backup, f"{no_backup} apparati senza backup della configurazione."),
                                  (unreadable, f"{unreadable} backup non leggibili.")) if n]
    notes += crowded
    if unknown:
        notes.append(f"{unknown} peer IPsec verso indirizzi che non sono apparati di questa organizzazione.")
    return ops, notes
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_blueprint_derive.py -v`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add services/blueprint_derive.py tests/test_blueprint_derive.py
git commit -m "feat(blueprint): derive subnets, gateways and VPN links from config backups"
```

---

### Task 4: `blueprint_assistant` service — describe, derive, instructions

**Model:** opus

**Files:**
- Create: `services/blueprint_assistant.py`
- Modify: `services/blueprint_model.py` (`OpError.__init__`, line 23)
- Modify: `services/blueprint.py` (`state`, lines 34–44; new `_ai_available`)
- Test: `tests/test_blueprint_assistant.py`

**Interfaces:**
- Consumes: `blueprint.state`, `blueprint.add_ops(org, ops, source, by)`, `blueprint_derive.derive` (Task 3), `inventory_store.read_instructions`/`write_instructions` (Task 1), `config_analyzer.analyze_device(ip, tenant)`, `classification_assist._extract_json(text) -> dict | None`, `routers.ai.chat_with_active_profile(messages) -> (reply, profile)` and `routers.ai._get_active_ai_profile() -> dict | None`.
- Produces:
  - `blueprint_model.OpError.reason: str` (message without the «Modifica N:» prefix)
  - `blueprint.state(org)` gains `"instructions": str` and `"ai_available": bool`; `blueprint._ai_available() -> bool`
  - `blueprint_assistant.MAX_TEXT = 4000`
  - `blueprint_assistant.describe(org: str, text: str, by: str) -> {"added": int, "notes": str, "state": dict}` — `ValueError` (422) on empty/too long text or two invalid answers; `HTTPException` from `chat_with_active_profile` passes through
  - `blueprint_assistant.derive(org: str, by: str, use_ai: bool) -> {"added": int, "notes": str, "state": dict}` — `ValueError` when nothing is derived (message carries the notes)
  - `blueprint_assistant.set_instructions(org: str, text: str) -> str` (stripped text; `ValueError` over `MAX_TEXT`)

- [ ] **Step 1: Write the failing tests** — `tests/test_blueprint_assistant.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Blueprint assistant: describe (fake LLM), derive, instructions (spec 2026-10-11)."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from ai import config_analyzer
from services import blueprint, blueprint_assistant, blueprint_store, inventory_manager, probe_manager
from tests.conftest import seed_inventory

LOCS = {"milano": {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.1.0/24"], "probe": "central"},
        "roma": {"org": "acme", "name": "Roma", "role": "branch", "subnets": [], "probe": "central"}}
HOSTS = [{"IP": "10.10.0.1", "Group": "acme", "Location": "milano"},
         {"IP": "10.20.0.1", "Group": "acme", "Location": "roma"}]
ROMA_FGT = {"interfaces": [{"name": "internal", "ip": "10.20.1.1/24", "status": "up"}],
            "routing": {"static": [{"prefix": "0.0.0.0/0"}]}, "vpn": {"phase1": [], "phase2": [], "peers": []}}


def reply(ops, notes=""):
    return json.dumps({"ops": ops, "notes": notes})


class _Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="bp_assist_")
        for p in (patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv")),
                  patch.object(probe_manager, "PROBES_JSON", os.path.join(tmp, "probes.json")),
                  patch("routers.ai._get_active_ai_profile", return_value={"provider": "ollama"})):
            p.start()
            self.addCleanup(p.stop)
        seed_inventory(orgs=["acme", "beta"], hosts=HOSTS, locations=LOCS)
        with inventory_manager._db() as conn, conn:
            blueprint_store.record_revisions(conn, "", "migration")

    def chat(self, *replies):
        p = patch("routers.ai.chat_with_active_profile",
                  side_effect=[r if isinstance(r, Exception) else (r, {"provider": "ollama"}) for r in replies])
        m = p.start()
        self.addCleanup(p.stop)
        return m

    def draft_ops(self):
        d = blueprint.state("acme")["draft"]
        return d["ops"] if d else []


class TestDescribe(_Base):
    def test_valid_answer_goes_to_the_draft(self):
        blueprint_assistant.set_instructions("acme", "Le filiali si chiamano come la città.")
        chat = self.chat(reply([{"op": "create_location", "ref": "+1", "name": "Torino", "role": "branch",
                                 "subnets": ["10.30.0.0/16"]},
                                {"op": "add_link", "a": "milano", "b": "+1", "kind": "vpn"}], "Torino aggiunta."))
        out = blueprint_assistant.describe("acme", "Aggiungi la filiale di Torino, 10.30.0.0/16, in VPN con Milano.", "adm")
        self.assertEqual((out["added"], out["notes"]), (2, "Torino aggiunta."))
        self.assertEqual([o["source"] for o in self.draft_ops()], ["assistant", "assistant"])
        self.assertIn("torino", out["state"]["preview"]["locations"])
        system, user = chat.call_args.args[0]
        self.assertEqual((system["role"], user["role"]), ("system", "user"))
        self.assertIn("Le filiali si chiamano come la città.", system["content"])
        self.assertIn('"id": "milano"', user["content"])
        self.assertIn("Aggiungi la filiale di Torino", user["content"])

    def test_fenced_json_is_accepted(self):
        self.chat("```json\n" + reply([{"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}]) + "\n```")
        self.assertEqual(blueprint_assistant.describe("acme", "Roma usa 10.20.1.0/24", "adm")["added"], 1)

    def test_invalid_then_valid_retries_once_with_the_error(self):
        chat = self.chat("Ecco la rete!", reply([{"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}]))
        out = blueprint_assistant.describe("acme", "Roma usa 10.20.1.0/24", "adm")
        self.assertEqual((chat.call_count, out["added"]), (2, 1))
        retry = chat.call_args_list[1].args[0]
        self.assertEqual(retry[-2], {"role": "assistant", "content": "Ecco la rete!"})
        self.assertIn('lista "ops"', retry[-1]["content"])

    def test_invalid_twice_is_a_value_error_and_no_draft(self):
        self.chat("boh", "ancora boh")
        with self.assertRaises(ValueError) as cm:
            blueprint_assistant.describe("acme", "Roma usa 10.20.1.0/24", "adm")
        self.assertIn('lista "ops"', str(cm.exception))
        self.assertEqual(self.draft_ops(), [])

    def test_non_object_ops_are_retried_then_422(self):
        self.chat(json.dumps({"ops": ["add roma"]}), json.dumps({"ops": [None]}))
        with self.assertRaises(ValueError) as cm:
            blueprint_assistant.describe("acme", "Roma usa 10.20.1.0/24", "adm")
        self.assertIn("operazione 1: non è un oggetto", str(cm.exception))

    def test_error_index_counts_only_the_reply(self):
        blueprint.add_ops("acme", [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"},
                                   {"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}], "manual", "adm")
        chat = self.chat(reply([{"op": "add_link", "a": "roma", "b": "roma", "kind": "vpn"}]),
                         reply([{"op": "add_subnet", "id": "milano", "subnet": "10.10.2.0/24"}]))
        out = blueprint_assistant.describe("acme", "Milano ha anche 10.10.2.0/24", "adm")
        self.assertIn("operazione 1: un collegamento unisce due sedi diverse",
                      chat.call_args_list[1].args[0][-1]["content"])
        self.assertEqual((out["added"], len(self.draft_ops())), (1, 3))

    def test_op_error_on_the_retry_too(self):
        bad = reply([{"op": "set_gateway", "id": "zara", "ip": "10.20.0.1"}])
        self.chat(bad, bad)
        with self.assertRaises(ValueError) as cm:
            blueprint_assistant.describe("acme", "Il gateway di Zara è 10.20.0.1", "adm")
        self.assertIn("operazione 1: sede 'zara' inesistente", str(cm.exception))

    def test_text_limits_never_reach_the_llm(self):
        chat = self.chat()
        for text in ("", "   ", "x" * (blueprint_assistant.MAX_TEXT + 1)):
            with self.subTest(n=len(text)), self.assertRaises(ValueError):
                blueprint_assistant.describe("acme", text, "adm")
        chat.assert_not_called()


class TestDerive(_Base):
    def analyses(self, table):
        p = patch.object(config_analyzer, "analyze_device", side_effect=lambda ip, tenant=None: table.get(ip))
        m = p.start()
        self.addCleanup(p.stop)
        return m

    def test_deterministic_ops_reach_the_draft(self):
        calls = self.analyses({"10.20.0.1": ROMA_FGT})
        out = blueprint_assistant.derive("acme", "adm", use_ai=False)
        self.assertEqual(out["added"], 2)
        self.assertEqual([(o["op"], o["source"]) for o in self.draft_ops()],
                         [("add_subnet", "assistant"), ("set_gateway", "assistant")])
        self.assertEqual(out["notes"], "1 apparati senza backup della configurazione.")
        self.assertEqual(calls.call_args.args[1], "acme")          # backups searched in the tenant

    def test_reads_the_preview(self):
        blueprint.add_ops("acme", [{"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}], "manual", "adm")
        self.analyses({"10.20.0.1": ROMA_FGT})
        out = blueprint_assistant.derive("acme", "adm", use_ai=False)
        self.assertEqual([o["op"] for o in self.draft_ops()], ["add_subnet", "set_gateway"])
        self.assertEqual(out["added"], 1)

    def test_nothing_derived_is_a_value_error_with_the_notes(self):
        self.analyses({})
        with self.assertRaises(ValueError) as cm:
            blueprint_assistant.derive("acme", "adm", use_ai=False)
        self.assertIn("Nessuna proposta dalle configurazioni.", str(cm.exception))
        self.assertIn("2 apparati senza backup", str(cm.exception))

    def test_a_backup_the_parser_chokes_on_is_counted(self):
        def boom(ip, tenant=None):
            if ip == "10.10.0.1":
                raise UnicodeError("x")
            return ROMA_FGT
        p = patch.object(config_analyzer, "analyze_device", side_effect=boom)
        p.start()
        self.addCleanup(p.stop)
        self.assertIn("1 backup non leggibili.", blueprint_assistant.derive("acme", "adm", use_ai=False)["notes"])

    def test_ai_pass_keeps_only_names_and_roles(self):
        self.analyses({"10.20.0.1": ROMA_FGT})
        self.chat(reply([{"op": "update_location", "id": "roma", "fields": {"name": "Roma EUR", "subnets": []}},
                         {"op": "update_location", "id": "milano", "fields": {"role": "datacenter"}},
                         {"op": "add_subnet", "id": "roma", "subnet": "10.99.0.0/16"},
                         {"op": "update_location", "id": "zara", "fields": {"name": "Zara"}},
                         "rinomina tutto"]))
        out = blueprint_assistant.derive("acme", "adm", use_ai=True)
        self.assertEqual(out["added"], 4)
        self.assertEqual([o.get("fields") for o in self.draft_ops()[2:]],
                         [{"name": "Roma EUR"}, {"role": "datacenter"}])

    def test_ai_failure_keeps_the_deterministic_ops(self):
        self.analyses({"10.20.0.1": ROMA_FGT})
        self.chat(HTTPException(status_code=502, detail="provider giù"))
        out = blueprint_assistant.derive("acme", "adm", use_ai=True)
        self.assertEqual(len(self.draft_ops()), 2)
        self.assertIn("provider giù", out["notes"])

    def test_ai_pass_skipped_without_a_profile(self):
        self.analyses({"10.20.0.1": ROMA_FGT})
        chat = self.chat()
        with patch("routers.ai._get_active_ai_profile", return_value=None):
            blueprint_assistant.derive("acme", "adm", use_ai=True)
        chat.assert_not_called()


class TestInstructions(_Base):
    def test_state_carries_them_and_the_ai_flag(self):
        self.assertEqual(blueprint_assistant.set_instructions("acme", "  Sedi: città.  "), "Sedi: città.")
        st = blueprint.state("acme")
        self.assertEqual((st["instructions"], st["ai_available"]), ("Sedi: città.", True))
        self.assertEqual(blueprint.state("beta")["instructions"], "")
        with patch("routers.ai._get_active_ai_profile", return_value=None):
            self.assertFalse(blueprint.state("acme")["ai_available"])

    def test_length_limit(self):
        with self.assertRaises(ValueError):
            blueprint_assistant.set_instructions("acme", "x" * (blueprint_assistant.MAX_TEXT + 1))
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_assistant.py -v`
Expected: FAIL — `ImportError: cannot import name 'blueprint_assistant'`.

- [ ] **Step 3: Implement**

`services/blueprint_model.py`, `OpError.__init__`:

```python
    def __init__(self, index: int, message: str):
        super().__init__(f"Modifica {index + 1}: {message}")
        self.index = index
        self.reason = message
```

`services/blueprint.py` — add after `_tables`:

```python
def _ai_available() -> bool:
    # Imported here: the AI profiles live in the AI router, which imports half
    # the application.
    from routers.ai import _get_active_ai_profile
    return _get_active_ai_profile() is not None
```

and replace `state`:

```python
def state(org: str) -> dict:
    with inventory_manager._db() as conn:
        locs, links = _tables(conn)
        draft = blueprint_store.get_draft(conn, org)
        revs = blueprint_store.revisions(conn, org)
        instructions = inventory_store.read_instructions(conn, org)
    preview, error = _preview(org, locs, links, draft)
    view = blueprint_model.org_view(locs, links, org)
    return {"org": org, "locations": view["locations"], "links": view["links"],
            "rev": revs[0]["rev"] if revs else 0, "rev_info": revs[0] if revs else None,
            "draft": draft, "preview": preview, "draft_error": error,
            "probes": [{"id": p["id"], "name": p.get("name") or p["id"]} for p in probe_manager.list_probes()],
            "instructions": instructions, "ai_available": _ai_available()}
```

`services/blueprint_assistant.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Blueprint assistant (spec 2026-10-11 blueprint-assistant): draft operations
from the operator's text («Descrivi la rete») and from the configuration
backups («Ricava dalle configurazioni»). Everything lands in the draft through
blueprint.add_ops with source «assistant»: nothing here applies a draft."""
import json

from fastapi import HTTPException

from ai import classification_assist, config_analyzer
from services import blueprint, blueprint_derive, blueprint_model, inventory_manager, inventory_store

MAX_TEXT = 4000

_OPS = """Operations (JSON objects):
- {"op": "create_location", "ref": "+1", "name": str, "role": "hq|branch|datacenter|warehouse|other", "subnets": [CIDR], "gateway": IPv4 or ""}
  "ref" starts with "+" and names the new location in later operations of the same answer.
- {"op": "update_location", "id": id, "fields": {"name"?, "role"?, "subnets"?, "gateway"?}}  ("subnets" replaces the whole list)
- {"op": "add_subnet", "id": id, "subnet": CIDR}
- {"op": "set_gateway", "id": id, "ip": IPv4 of a device of that location}
- {"op": "delete_location", "id": id}
- {"op": "add_link", "a": id or ref, "b": id or ref, "kind": "vpn|wan|mpls|lan", "note": str}
- {"op": "remove_link", "id": a link id of the model}
"id" is a location id of the current model or a "+ref" created earlier in the same answer."""


def _view(st: dict) -> dict:
    return st["preview"] or {"locations": st["locations"], "links": st["links"]}


def _model(st: dict) -> str:
    view = _view(st)
    return json.dumps({
        "locations": [{"id": k, "name": l["name"], "role": l["role"], "subnets": l["subnets"],
                       "gateway": l.get("gateway") or ""} for k, l in sorted(view["locations"].items())],
        "links": [{"id": k, "a": v["a"], "b": v["b"], "kind": v["kind"]} for k, v in sorted(view["links"].items())],
    }, ensure_ascii=False)


def _conventions(instructions: str) -> str:
    return f"\n\nConventions of this organization (follow them):\n{instructions}" if instructions else ""


def _chat(messages: list) -> str:
    from routers.ai import chat_with_active_profile
    return chat_with_active_profile(messages)[0]


def _parse(reply: str):
    data = classification_assist._extract_json(reply)
    if data is None or not isinstance(data.get("ops"), list):
        raise ValueError('la risposta non è un oggetto JSON con una lista "ops"')
    for i, op in enumerate(data["ops"]):
        if not isinstance(op, dict):
            raise ValueError(f"operazione {i + 1}: non è un oggetto")
    return data["ops"], str(data.get("notes") or "")


def describe(org: str, text: str, by: str) -> dict:
    text = (text or "").strip()
    if not text:
        raise ValueError("Descrivi la rete: il testo è vuoto.")
    if len(text) > MAX_TEXT:
        raise ValueError(f"Testo troppo lungo: massimo {MAX_TEXT} caratteri.")
    st = blueprint.state(org)
    before = len(st["draft"]["ops"]) if st["draft"] else 0
    system = ("You turn an operator's description of a network into draft operations for the Network "
              "Blueprint of ONE organization in SentinelNet. A human reviews the draft before anything "
              "is applied.\n\n" + _OPS + "\n\nRules: change only this organization; never delete a location "
              "or a link unless the text asks for it; subnets in CIDR; do not repeat what the model already "
              "has." + _conventions(st["instructions"]) + '\n\nReply with one JSON object and nothing else: '
              '{"ops": [...], "notes": "short remarks for the operator, in the operator\'s language"}.')
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": f"Current model:\n{_model(st)}\n\nOperator:\n{text}"}]
    error = ""
    for _attempt in range(2):
        answer = _chat(messages)
        try:
            ops, notes = _parse(answer)
            return {"added": len(ops), "notes": notes, "state": blueprint.add_ops(org, ops, "assistant", by)}
        except blueprint_model.OpError as e:
            # apply_ops numbers the whole draft; the LLM knows only its own ops.
            error = f"operazione {e.index - before + 1}: {e.reason}" if e.index >= before else str(e)
        except ValueError as e:
            error = str(e)
        # A new list each time: the first call's messages stay as they were sent.
        messages = messages + [{"role": "assistant", "content": answer},
                               {"role": "user", "content": f"Error: {error}. Fix it and reply with the JSON object only."}]
    raise ValueError(f"L'assistente non ha prodotto una bozza valida: {error}")


def _renames(st: dict, derived: list) -> list:
    """Optional AI pass of derive: only update_location on existing locations,
    only name and role; anything else is dropped before validation."""
    view = _view(st)
    system = ("You review locations of ONE organization in SentinelNet. From the model and the operations "
              "derived from its configuration backups, propose better location names and roles. You may only "
              'answer {"op": "update_location", "id": id, "fields": {"name"?, "role"?}} operations on the '
              "locations listed; roles: hq|branch|datacenter|warehouse|other." + _conventions(st["instructions"])
              + '\n\nReply with one JSON object and nothing else: {"ops": [...]}.')
    answer = _chat([{"role": "system", "content": system},
                    {"role": "user", "content": f"Current model:\n{_model(st)}\n\nDerived operations:\n"
                                                f"{json.dumps(derived, ensure_ascii=False)}"}])
    data = classification_assist._extract_json(answer) or {}
    out = []
    for op in data.get("ops") if isinstance(data.get("ops"), list) else []:
        if not isinstance(op, dict) or op.get("op") != "update_location" or op.get("id") not in view["locations"]:
            continue
        fields = op.get("fields") if isinstance(op.get("fields"), dict) else {}
        fields = {k: v for k, v in fields.items() if k in ("name", "role")}
        if fields:
            out.append({"op": "update_location", "id": op["id"], "fields": fields})
    return out


def derive(org: str, by: str, use_ai: bool) -> dict:
    st = blueprint.state(org)
    view = _view(st)
    devices = [d for d in inventory_manager.get_all_devices() if d.get("Group") == org]
    analyses = {}
    for d in devices:
        if d.get("Location") in view["locations"]:
            try:
                analyses[d["IP"]] = config_analyzer.analyze_device(d["IP"], org)
            except Exception:  # an unreadable backup is counted in the notes, not fatal for the others
                analyses[d["IP"]] = {}
    ops, notes = blueprint_derive.derive(view, devices, analyses)
    if not ops:
        raise ValueError(" ".join(["Nessuna proposta dalle configurazioni."] + notes))
    # The deterministic ops go in first: the AI pass failing never loses them.
    out = blueprint.add_ops(org, ops, "assistant", by)
    added = len(ops)
    if use_ai and st["ai_available"]:
        try:
            renames = _renames(out, ops)
            if renames:
                out = blueprint.add_ops(org, renames, "assistant", by)
                added += len(renames)
        except (HTTPException, ValueError) as e:
            notes.append("Passaggio AI non riuscito, restano le proposte dalle configurazioni: "
                         f"{getattr(e, 'detail', None) or e}")
    return {"added": added, "notes": "\n".join(notes), "state": out}


def set_instructions(org: str, text: str) -> str:
    text = (text or "").strip()
    if len(text) > MAX_TEXT:
        raise ValueError(f"Istruzioni troppo lunghe: massimo {MAX_TEXT} caratteri.")
    with inventory_manager._db() as conn:
        inventory_store.write_instructions(conn, org, text)
    return text
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_blueprint_assistant.py tests/test_blueprint_api.py tests/test_blueprint_model.py -v`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add services/blueprint_assistant.py services/blueprint_model.py services/blueprint.py tests/test_blueprint_assistant.py
git commit -m "feat(blueprint): assistant service - describe, derive, instructions"
```

---

### Task 5: Assistant routes — describe, derive, instructions

**Model:** sonnet

**Files:**
- Modify: `routers/blueprint.py` (imports, schemas, three routes at the end)
- Modify: `tests/test_router_parity.py` (`NEW_SCHEMAS`, the tuple ending `"DraftAddSchema", "DraftReplaceSchema", "ApplySchema")`)
- Test: `tests/test_blueprint_assistant_api.py`

**Interfaces:**
- Consumes: `blueprint_assistant.describe`, `derive`, `set_instructions` (Task 4); router helpers `_org`, `_call`, `_TAB`.
- Produces (HTTP, all admin, `tab-blueprint`, tenant-checked):
  - `POST /api/blueprint/{org}/assistant/describe` `{text}` → `{"added", "notes", "state"}`
  - `POST /api/blueprint/{org}/assistant/derive` `{use_ai: bool = false}` → same
  - `PUT /api/blueprint/{org}/instructions` `{text}` → `{"instructions": str}`
  - `GET /api/blueprint/{org}` now carries `instructions`, `ai_available` (Task 4)

- [ ] **Step 1: Write the failing tests** — `tests/test_blueprint_assistant_api.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""/api/blueprint assistant routes (spec 2026-10-11 blueprint-assistant)."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from ai import config_analyzer
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager
from services import blueprint_observe, blueprint_store, inventory_manager, probe_manager
from tests.conftest import seed_inventory

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"
LOCS = {"milano": {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.0.0/16"], "probe": "central"},
        "roma": {"org": "acme", "name": "Roma", "role": "branch", "subnets": [], "probe": "central"}}
EMPTY_OBS = {"devices": [], "arp": [], "routes": {}, "tunnels": {}, "observed_at": None}
SUBNET = [{"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}]


class _Api(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="bp_assist_api_")
        self.tmp = tmp
        for p in (patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv")),
                  patch.object(probe_manager, "PROBES_JSON", os.path.join(tmp, "probes.json")),
                  patch.object(user_manager, "USERS_JSON", os.path.join(tmp, "users.json")),
                  patch.object(blueprint_observe, "gather", return_value=EMPTY_OBS),
                  patch("routers.ai._get_active_ai_profile", return_value={"provider": "ollama"})):
            p.start()
            self.addCleanup(p.stop)
        security_manager._failed_attempts.clear()
        seed_inventory(orgs=["acme", "beta"], hosts=[{"IP": "10.20.0.1", "Group": "acme", "Location": "roma"}],
                       locations=LOCS)
        with inventory_manager._db() as conn, conn:
            blueprint_store.record_revisions(conn, "", "migration")
        user_manager.create_user("adm", PW, role="admin")
        user_manager.create_user("admbeta", PW, role="admin", groups=["beta"])
        user_manager.create_user("view", PW, role="viewer")
        self.c = self._as("adm")

    def _as(self, name):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        c.headers.update(H)
        return c


def fake_chat(*replies):
    return patch("routers.ai.chat_with_active_profile", side_effect=[(r, {"provider": "ollama"}) for r in replies])


class TestDescribe(_Api):
    def test_admin_gets_a_draft(self):
        with fake_chat(json.dumps({"ops": SUBNET, "notes": "ok"})):
            r = self.c.post("/api/blueprint/acme/assistant/describe", json={"text": "Roma usa 10.20.1.0/24"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((r.json()["added"], r.json()["notes"]), (1, "ok"))
        self.assertEqual(r.json()["state"]["draft"]["ops"][0]["source"], "assistant")

    def test_gates(self):
        with fake_chat() as chat:
            for who in ("view", "admbeta"):
                with self.subTest(who=who):
                    r = self._as(who).post("/api/blueprint/acme/assistant/describe", json={"text": "x"})
                    self.assertEqual(r.status_code, 403)
        chat.assert_not_called()

    def test_invalid_twice_and_empty_text_are_422(self):
        with fake_chat("boh", "boh"):
            r = self.c.post("/api/blueprint/acme/assistant/describe", json={"text": "Roma usa 10.20.1.0/24"})
        self.assertEqual(r.status_code, 422)
        self.assertIn("bozza valida", r.json()["detail"]["message"])
        self.assertEqual(self.c.post("/api/blueprint/acme/assistant/describe", json={"text": " "}).status_code, 422)

    def test_no_active_profile_keeps_the_ai_tab_error(self):
        with patch("routers.ai._get_active_ai_profile", return_value=None):
            r = self.c.post("/api/blueprint/acme/assistant/describe", json={"text": "Roma usa 10.20.1.0/24"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("profilo AI", r.json()["detail"])


class TestDerive(_Api):
    def test_nothing_derived_is_422_with_the_notes(self):
        with patch.object(config_analyzer, "analyze_device", return_value=None):
            r = self.c.post("/api/blueprint/acme/assistant/derive", json={})
        self.assertEqual(r.status_code, 422)
        self.assertIn("senza backup", r.json()["detail"]["message"])

    def test_derived_ops_reach_the_draft(self):
        backup = {"interfaces": [{"name": "internal", "ip": "10.20.1.1/24"}], "routing": {"static": []}, "vpn": []}
        with patch.object(config_analyzer, "analyze_device", return_value=backup):
            r = self.c.post("/api/blueprint/acme/assistant/derive", json={"use_ai": False})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["added"], 1)
        self.assertEqual(self._as("view").post("/api/blueprint/acme/assistant/derive", json={}).status_code, 403)


class TestInstructions(_Api):
    def test_round_trip_limit_and_gates(self):
        r = self.c.put("/api/blueprint/acme/instructions", json={"text": "  Sedi col nome della città.  "})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"instructions": "Sedi col nome della città."})
        st = self.c.get("/api/blueprint/acme").json()
        self.assertEqual((st["instructions"], st["ai_available"]), ("Sedi col nome della città.", True))
        self.assertEqual(self.c.put("/api/blueprint/acme/instructions", json={"text": "x" * 4001}).status_code, 422)
        self.assertEqual(self._as("view").put("/api/blueprint/acme/instructions", json={"text": "y"}).status_code, 403)
        self.assertEqual(self._as("admbeta").put("/api/blueprint/acme/instructions", json={"text": "y"}).status_code, 403)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_assistant_api.py -v`
Expected: FAIL — 404/405 on the new routes.

- [ ] **Step 3: Implement** — `routers/blueprint.py`.

Imports:

```python
from services import blueprint, blueprint_assistant, inventory_manager
```

Schemas, after `ApplySchema`:

```python
class AssistantDescribeSchema(BaseModel):
    text: str


class AssistantDeriveSchema(BaseModel):
    use_ai: bool = False


class InstructionsSchema(BaseModel):
    text: str
```

Routes, at the end of the file:

```python
# --- Assistant (spec 2026-10-11 blueprint-assistant) ------------------------
# Every route below only appends to the draft; applying stays a human action.

@router.post("/api/blueprint/{org}/assistant/describe", dependencies=_TAB)
def assistant_describe_ep(org: str, payload: AssistantDescribeSchema, current_user=Depends(require_admin)):
    _org(org, current_user)
    who = current_user.get("sub")
    out = _call(blueprint_assistant.describe, org, payload.text, who)
    log_audit(f"Blueprint '{org}': {out['added']} modifiche proposte dall'assistente (descrizione) "
              f"per l'utente '{who}'.")
    return out


@router.post("/api/blueprint/{org}/assistant/derive", dependencies=_TAB)
def assistant_derive_ep(org: str, payload: AssistantDeriveSchema, current_user=Depends(require_admin)):
    _org(org, current_user)
    who = current_user.get("sub")
    out = _call(blueprint_assistant.derive, org, who, payload.use_ai)
    log_audit(f"Blueprint '{org}': {out['added']} modifiche ricavate dalle configurazioni "
              f"per l'utente '{who}'.")
    return out


@router.put("/api/blueprint/{org}/instructions", dependencies=_TAB)
def instructions_ep(org: str, payload: InstructionsSchema, current_user=Depends(require_admin)):
    _org(org, current_user)
    text = _call(blueprint_assistant.set_instructions, org, payload.text)
    log_audit(f"Blueprint '{org}': istruzioni dell'assistente aggiornate dall'utente '{current_user.get('sub')}'.")
    return {"instructions": text}
```

`tests/test_router_parity.py`, the `NEW_SCHEMAS` tuple — replace its last line:

```python
                    "DraftAddSchema", "DraftReplaceSchema", "ApplySchema",
                    # Blueprint assistant (spec 2026-10-11, routes under /api/blueprint).
                    "AssistantDescribeSchema", "AssistantDeriveSchema", "InstructionsSchema")
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_blueprint_assistant_api.py tests/test_blueprint_api.py tests/test_router_parity.py tests/test_tab_enforcement.py -v`
Expected: PASS.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add routers/blueprint.py tests/test_blueprint_assistant_api.py tests/test_router_parity.py
git commit -m "feat(blueprint): assistant routes - describe, derive, instructions"
```

---

### Task 6: MCP permission `bp_draft` and the `assistant-draft` route

**Model:** opus

**Files:**
- Modify: `security/mcp_grants.py` (`create_code`, `redeem_code`, `user_for_grant`)
- Modify: `routers/mcp.py` (`McpAuthorizeSchema`, `mcp_authorize_info`, `authorize_mcp_client`, `open_mcp_session`)
- Modify: `routers/blueprint.py` (`_drafter`, `AssistantDraftSchema`, route)
- Modify: `templates/mcp_authorize.html`, `static/js/mcp-authorize.js`, `static/js/i18n.js` (consent checkbox)
- Modify: `tests/test_router_parity.py` (`NEW_SCHEMAS`)
- Test: `tests/test_blueprint_assistant_api.py` (append classes)

**Interfaces:**
- Consumes: `user_manager.is_admin(role)`, `user_manager.get_role(user)`, `security_manager.verify_access_token`, `blueprint.add_ops`.
- Produces:
  - `mcp_grants.create_code(username, challenge, label, read_only, bp_draft=False) -> str`; grants store `"bp_draft": bool`; `user_for_grant(token) -> {"user", "read_only", "bp_draft"}`
  - `McpAuthorizeSchema.bp_draft: bool = False`; `/api/mcp/authorize/info` gains `"can_bp_draft": bool`
  - session JWT: `ro` and, for `bp_draft` grants of a user who is an admin at session time, `bpd: true`
  - `POST /api/blueprint/{org}/assistant-draft` `{ops: list, note: str ≤ 500}` → `state(org)` (used by the MCP tool in Task 7)

- [ ] **Step 1: Write the failing tests** — append to `tests/test_blueprint_assistant_api.py` (add the imports at the top of the file):

```python
import pathlib
from urllib.parse import parse_qs, urlparse

from security import mcp_grants
from security.security_manager import verify_access_token

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFIER = "v" * 64
CHALLENGE = mcp_grants.challenge_for(VERIFIER)


class _Mcp(_Api):
    def setUp(self):
        super().setUp()
        p = patch.object(mcp_grants, "_path", return_value=os.path.join(self.tmp, "mcp_grants.json"))
        p.start()
        self.addCleanup(p.stop)
        user_manager.create_user("oper", PW, role="operator")

    def grant(self, client, **extra):
        r = client.post("/api/mcp/authorize", json={"port": 38461, "state": "state-123", "challenge": CHALLENGE,
                                                    "client": "Claude Desktop", **extra})
        self.assertEqual(r.status_code, 200, r.text)
        code = parse_qs(urlparse(r.json()["redirect"]).query)["code"][0]
        r = TestClient(app_server.app).post("/api/mcp/token", json={"code": code, "verifier": VERIFIER})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["token"]

    def session(self, grant):
        r = TestClient(app_server.app).post("/api/mcp/session", json={"token": grant})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["access_token"]

    def claims(self, client, **extra):
        return verify_access_token(self.session(self.grant(client, **extra)))

    def bearer(self, client, **extra):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        c.headers["Authorization"] = "Bearer " + self.session(self.grant(client, **extra))
        return c

    def propose(self, c, org="acme", ops=SUBNET):
        return c.post(f"/api/blueprint/{org}/assistant-draft", json={"ops": ops, "note": "da\nClaude"})


class TestGrantPermission(_Mcp):
    def test_bpd_only_for_read_only_admin_grants(self):
        claims = self.claims(self.c, read_only=True, bp_draft=True)
        self.assertEqual((claims.get("ro"), claims.get("bpd")), (True, True))
        self.assertNotIn("bpd", self.claims(self.c, read_only=True))
        self.assertNotIn("bpd", self.claims(self.c, read_only=False, bp_draft=True))   # full grant: not needed
        self.assertNotIn("bpd", self.claims(self._as("oper"), read_only=True, bp_draft=True))
        oper_grants = mcp_grants.list_grants("oper")
        self.assertTrue(oper_grants)
        self.assertFalse(any(mcp_grants._load()[g["id"]].get("bp_draft") for g in oper_grants))

    def test_user_demoted_before_the_session_gets_no_bpd(self):
        grant = self.grant(self.c, read_only=True, bp_draft=True)
        user_manager.set_role("adm", "operator")
        claims = verify_access_token(self.session(grant))
        self.assertTrue(claims["ro"])
        self.assertNotIn("bpd", claims)

    def test_consent_offers_it_to_admins_only(self):
        self.assertTrue(self.c.get("/api/mcp/authorize/info").json()["can_bp_draft"])
        self.assertFalse(self._as("oper").get("/api/mcp/authorize/info").json()["can_bp_draft"])
        html = (ROOT / "templates/mcp_authorize.html").read_text(encoding="utf-8")
        js = (ROOT / "static/js/mcp-authorize.js").read_text(encoding="utf-8")
        self.assertIn('id="mcpcBpDraft"', html)
        self.assertIn('id="mcpcBpBox"', html)
        self.assertIn("bp_draft:", js)


class TestAssistantDraft(_Mcp):
    def test_admin_session_appends_with_source_assistant(self):
        with patch("routers.blueprint.log_audit") as audit:
            r = self.propose(self.c)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["draft"]["ops"][0]["source"], "assistant")
        self.assertIn("da Claude", audit.call_args.args[0])
        self.assertIn("1 modifiche", audit.call_args.args[0])

    def test_read_only_grant_with_bp_draft_appends_and_nothing_else(self):
        c = self.bearer(self.c, read_only=True, bp_draft=True)
        self.assertEqual(self.propose(c).status_code, 200)
        self.assertEqual(c.get("/api/auth/me").json()["role"], "viewer")
        self.assertEqual(c.post("/api/blueprint/acme/draft", json={"ops": SUBNET}).status_code, 403)
        self.assertEqual(c.post("/api/blueprint/acme/draft/apply", json={}).status_code, 403)
        self.assertEqual(c.post("/api/blueprint/acme/assistant/describe", json={"text": "x"}).status_code, 403)

    def test_read_only_grant_without_bp_draft_is_refused(self):
        self.assertEqual(self.propose(self.bearer(self.c, read_only=True)).status_code, 403)

    def test_demoted_user_loses_it_at_once(self):
        c = self.bearer(self.c, read_only=True, bp_draft=True)
        user_manager.set_role("adm", "operator")
        self.assertEqual(self.propose(c).status_code, 403)

    def test_other_tenant_viewer_and_operator_are_refused(self):
        for who in ("admbeta", "view", "oper"):
            with self.subTest(who=who):
                self.assertEqual(self.propose(self._as(who)).status_code, 403)

    def test_invalid_op_is_422_with_its_index(self):
        r = self.propose(self.c, ops=[{"op": "add_link", "a": "roma", "b": "roma", "kind": "vpn"}])
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.json()["detail"]["index"], 0)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_assistant_api.py -k "Grant or AssistantDraft" -v`
Expected: FAIL — `KeyError: 'can_bp_draft'`, 404 on `assistant-draft`, no `bpd` claim.

- [ ] **Step 3: Implement**

`security/mcp_grants.py`:

```python
def create_code(username: str, challenge: str, label: str, read_only: bool, bp_draft: bool = False) -> str:
    """``label`` names the client on the grant list; ``read_only`` makes every
    session of the grant a viewer session whatever the user's role;
    ``bp_draft`` lets a read-only session append Blueprint draft operations
    (spec 2026-10-11 blueprint-assistant)."""
    code = secrets.token_urlsafe(32)
    now = time.time()
    with _lock:
        for k in [k for k, v in _codes.items() if v["exp"] <= now]:
            _codes.pop(k, None)
        _codes[code] = {"user": username, "challenge": challenge, "label": label[:80],
                        "read_only": read_only, "bp_draft": bp_draft, "exp": now + CODE_TTL_SECONDS}
    return code
```

In `redeem_code`, the stored grant gains `"bp_draft": entry["bp_draft"],` after `"read_only": entry["read_only"],`. In `user_for_grant`, the return becomes:

```python
    return {"user": user, "read_only": bool(g.get("read_only")), "bp_draft": bool(g.get("bp_draft"))}
```

`routers/mcp.py` — `McpAuthorizeSchema` gains, after `read_only: bool = True`:

```python
    bp_draft: bool = False
```

`mcp_authorize_info` returns, in addition:

```python
            "can_bp_draft": user_manager.is_admin(role),
```

`authorize_mcp_client`:

```python
    user = current_user.get("sub")
    read_only = payload.read_only or _ROLE_RANK.get(current_user.get("role"), 0) == 0
    # The one write a read-only grant may carry, and only an admin can lend it
    # (spec 2026-10-11 blueprint-assistant). A full grant reaches the normal
    # draft routes anyway.
    bp_draft = payload.bp_draft and read_only and user_manager.is_admin(current_user.get("role"))
    label = " · ".join(x for x in (payload.client or "Client MCP", payload.host) if x)
    code = mcp_grants.create_code(user, payload.challenge, label, read_only, bp_draft)
    log_audit(f"Client MCP '{label}' autorizzato da '{user}' "
              f"({'sola lettura' if read_only else 'permessi del ruolo'}"
              f"{' + bozze Blueprint' if bp_draft else ''}).")
```

`open_mcp_session`:

```python
    if grant["read_only"]:
        claims["ro"] = True    # get_current_user turns it into a viewer session
        # Next to «ro», never instead of it: the session stays a viewer
        # everywhere but POST /api/blueprint/{org}/assistant-draft.
        if grant["bp_draft"] and user_manager.is_admin(claims["role"]):
            claims["bpd"] = True
```

`routers/blueprint.py` — imports:

```python
from pydantic import BaseModel, Field

from security import user_manager
```

Schema, after `InstructionsSchema`:

```python
class AssistantDraftSchema(BaseModel):
    ops: List[dict]
    note: str = Field(default="", max_length=500)
```

Dependency, after `_call`:

```python
def _drafter(current_user=Depends(get_current_user)):
    """An admin session, or a read-only MCP session lent «bpd» (spec
    2026-10-11 blueprint-assistant). The role is read from disk, not from the
    token: a user demoted after the session opened loses the right at once."""
    if not user_manager.is_admin(user_manager.get_role(current_user.get("sub"))) or \
            (current_user.get("ro") and not current_user.get("bpd")):
        raise HTTPException(status_code=403, detail="Serve un amministratore, o un client MCP autorizzato "
                                                    "a proporre bozze del Blueprint.")
    return current_user
```

Route, at the end of the file:

```python
@router.post("/api/blueprint/{org}/assistant-draft", dependencies=_TAB)
def assistant_draft_ep(org: str, payload: AssistantDraftSchema, current_user=Depends(_drafter)):
    """Append-only door for MCP clients: no preset, restore, apply, discard,
    align. The source is always «assistant»."""
    _org(org, current_user)
    who = current_user.get("sub")
    out = _call(blueprint.add_ops, org, payload.ops, "assistant", who)
    note = " ".join(payload.note.split())
    log_audit(f"Blueprint '{org}': {len(payload.ops)} modifiche proposte via MCP dall'utente '{who}'"
              + (f" — nota: {note}" if note else "") + ".")
    return out
```

`tests/test_router_parity.py`, `NEW_SCHEMAS` last line becomes:

```python
                    "AssistantDescribeSchema", "AssistantDeriveSchema", "InstructionsSchema", "AssistantDraftSchema")
```

Consent page — `templates/mcp_authorize.html`, right after the `mcpcRoBox` label:

```html
        <label class="consent-ro" id="mcpcBpBox" hidden>
          <input type="checkbox" id="mcpcBpDraft">
          <span data-i18n="mcpcBpDraft">Consenti di proporre bozze del Blueprint — le applica solo un amministratore.</span>
        </label>
```

`static/js/mcp-authorize.js` — in `mcpcRenderPerms`, right after `const ro = …`:

```js
    // Read-only grants of an admin may also propose Blueprint drafts.
    mcpcEl('mcpcBpBox').hidden = !(mcpcInfo.can_bp_draft && ro);
```

and in the approve handler body, after `read_only: …,`:

```js
            bp_draft: !mcpcEl('mcpcBpBox').hidden && mcpcEl('mcpcBpDraft').checked,
```

`static/js/i18n.js` — after `mcpcReadOnly: …` in `it`:

```js
        mcpcBpDraft: "Consenti di proporre bozze del Blueprint — le applica solo un amministratore.",
```

and after `mcpcReadOnly: …` in `en`:

```js
        mcpcBpDraft: "Allow proposing Blueprint drafts — only an admin applies them.",
```

- [ ] **Step 4: Run tests**

Run:
```bash
uv run pytest tests/test_blueprint_assistant_api.py tests/test_mcp_browser_login.py tests/test_router_parity.py tests/test_i18n_keys.py -v
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
```
Expected: PASS / zero findings.

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run python scripts/check_frontend.py && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add security/mcp_grants.py routers/mcp.py routers/blueprint.py templates/mcp_authorize.html static/js/mcp-authorize.js static/js/i18n.js tests/test_blueprint_assistant_api.py tests/test_router_parity.py
git commit -m "feat(mcp): read-only grants may propose Blueprint drafts (bp_draft)"
```

---

### Task 7: MCP tools `blueprint_get` and `blueprint_propose`

**Model:** sonnet

**Files:**
- Modify: `ai/mcp_server.py` (import `quote`; two `TOOLS` entries after `get_device_classification`)
- Test: `tests/test_mcp_server_tools.py` (append a class); `tests/test_mcp_tool_routes.py` covers the routes unchanged

**Interfaces:**
- Consumes: `GET /api/blueprint/{org}`, `GET /api/blueprint/{org}/checks`, `POST /api/blueprint/{org}/assistant-draft` (Task 6).
- Produces: `mcp_server.TOOLS["blueprint_get"]`, `mcp_server.TOOLS["blueprint_propose"]`.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_mcp_server_tools.py`:

```python
class TestBlueprintTools(unittest.TestCase):
    OPS = [{"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}]

    def test_get_reads_model_and_checks(self):
        _desc, schema, fn = mcp_server.TOOLS["blueprint_get"]
        self.assertEqual(schema["required"], ["org"])
        with patch("ai.mcp_server.api", return_value={"x": 1}) as mock_api:
            out = fn({"org": "acme"})
        self.assertEqual([c.args for c in mock_api.call_args_list],
                         [("GET", "/api/blueprint/acme"), ("GET", "/api/blueprint/acme/checks")])
        self.assertEqual(out, {"blueprint": {"x": 1}, "checks": {"x": 1}})

    def test_propose_posts_to_the_assistant_draft_route(self):
        _desc, schema, fn = mcp_server.TOOLS["blueprint_propose"]
        self.assertEqual(schema["required"], ["org", "ops"])
        with patch("ai.mcp_server.api") as mock_api:
            fn({"org": "acme", "ops": self.OPS})
        mock_api.assert_called_once_with("POST", "/api/blueprint/acme/assistant-draft",
                                         body={"ops": self.OPS, "note": ""})

    def test_org_is_escaped_in_the_path(self):
        _desc, _schema, fn = mcp_server.TOOLS["blueprint_propose"]
        with patch("ai.mcp_server.api") as mock_api:
            fn({"org": "a b/c", "ops": [], "note": "n"})
        self.assertEqual(mock_api.call_args.args[1], "/api/blueprint/a%20b%2Fc/assistant-draft")
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_mcp_server_tools.py -k Blueprint -v`
Expected: FAIL — `KeyError: 'blueprint_get'`.

- [ ] **Step 3: Implement** — `ai/mcp_server.py`.

Import line:

```python
from urllib.parse import parse_qs, quote, urlencode, urlparse
```

`TOOLS`, after `get_device_classification`:

```python
    # Network Blueprint (spec 2026-10-11 blueprint-assistant). Proposing only
    # appends to the draft: an admin reviews and applies it in the Blueprint tab.
    "blueprint_get": (
        "Network Blueprint of an organization: expected locations (role, subnets, "
        "gateway), links between them, the open draft and its preview, plus the "
        "deterministic checks comparing it with the observed network.",
        _obj({"org": {**_S, "description": "Organization (tenant) key"}}, ["org"]),
        lambda a: {"blueprint": api("GET", f"/api/blueprint/{quote(a['org'], safe='')}"),
                   "checks": api("GET", f"/api/blueprint/{quote(a['org'], safe='')}/checks")},
    ),
    "blueprint_propose": (
        "Propose changes to an organization's Network Blueprint. They are appended "
        "to its draft and never applied: an admin reviews and applies them. "
        "Operations: create_location {ref:'+1', name, role: hq|branch|datacenter|"
        "warehouse|other, subnets:[CIDR], gateway}, update_location {id, fields}, "
        "add_subnet {id, subnet}, set_gateway {id, ip}, delete_location {id}, "
        "add_link {a, b, kind: vpn|wan|mpls|lan, note}, remove_link {id}. Ids come "
        "from blueprint_get; a '+ref' names a location created earlier in the same "
        "list. Needs an admin account, or a read-only sign-in where 'propose "
        "Blueprint drafts' was allowed.",
        _obj({"org": {**_S, "description": "Organization (tenant) key"},
              "ops": {"type": "array", "items": {"type": "object"},
                      "description": "Draft operations, applied in order"},
              "note": {**_S, "description": "Why, for the audit log (optional)"}},
             ["org", "ops"]),
        lambda a: api("POST", f"/api/blueprint/{quote(a['org'], safe='')}/assistant-draft",
                      body={"ops": a["ops"], "note": a.get("note", "")}),
    ),
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_mcp_server_tools.py tests/test_mcp_tool_routes.py tests/test_mcp_browser_login.py -v`
Expected: PASS (`test_mcp_tool_routes` sends `blueprint_*` unauthenticated → 401, i.e. a handler matched).

- [ ] **Step 5: Gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add ai/mcp_server.py tests/test_mcp_server_tools.py
git commit -m "feat(mcp): blueprint_get and blueprint_propose tools"
```

---

### Task 8: Blueprint tab — «Assistente» and «Istruzioni assistente»

**Model:** opus

**Files:**
- Modify: `templates/dashboard.html` (two buttons after `btnBpHistory` ~line 1050; two modals right before `<!-- Which location of an organization (pickLocation, core.js). -->`)
- Modify: `static/js/blueprint.js` (assistant section before «bindings»; bindings; source tag in `renderDraftOps`)
- Modify: `static/js/i18n.js` (keys after `bpObserved` in `it` and `en`), `static/css/dashboard.css`
- Test: `tests/test_blueprint_tab.py` (append a class)

**Interfaces:**
- Consumes: Task 5 routes, `state.instructions`, `state.ai_available`; in-module helpers `$`, `send`, `errorText`, `reloadBlueprint`, `draftOps`, `describeOp`; globals `tr`, `escapeHtml`, `showToast`, `openModal`, `closeModal`. Reused i18n keys: `bpAddedToDraft`, `btnClose`, `uiCancel`, `uiSave`.
- Produces: nothing cross-module (no new `window.*`, no `globals.d.ts` entry).

- [ ] **Step 1: Write the failing test** — append to `tests/test_blueprint_tab.py`:

```python
ASSIST_IDS = ("btnBpAssistant", "btnBpInstructions", "bpAssistantModal", "bpAssistText", "btnBpAssistDescribe",
              "bpAssistUseAi", "btnBpAssistDerive", "bpAssistError", "bpAssistNotes",
              "bpInstructionsModal", "bpInstrText", "bpInstrError", "btnBpInstrSave")


class TheAssistantIsWired(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
        self.js = (ROOT / "static/js/blueprint.js").read_text(encoding="utf-8")
        self.i18n = (ROOT / "static/js/i18n.js").read_text(encoding="utf-8")

    def test_every_control_exists_and_the_buttons_are_bound(self):
        for element_id in ASSIST_IDS:
            self.assertIn(f'id="{element_id}"', self.html, element_id)
        for button in ("btnBpAssistant", "btnBpInstructions", "btnBpAssistDescribe", "btnBpAssistDerive",
                       "btnBpInstrSave"):
            self.assertIn(f"$('{button}').addEventListener", self.js, button)

    def test_routes_ai_flag_and_source_tag(self):
        for needle in ("'/assistant/describe'", "'/assistant/derive'", "'/instructions'",
                       "$('bpAssistUseAi').disabled = !bpState.ai_available", "tr('bpOpFromAssistant')"):
            self.assertIn(needle, self.js, needle)

    def test_keys_in_both_languages(self):
        it, en = self.i18n.split("\n    en: {", 1)
        for key in ("btnBpAssistant", "btnBpInstructions", "bpAssistModalTitle", "bpAssistHint",
                    "bpAssistDescribeTitle", "lblBpAssistText", "bpAssistTextPh", "btnBpAssistDescribe",
                    "bpAssistDeriveTitle", "bpAssistDeriveHint", "lblBpAssistUseAi", "btnBpAssistDerive",
                    "bpInstrModalTitle", "bpInstrHint", "lblBpInstrText", "bpInstrSaved", "bpOpFromAssistant"):
            with self.subTest(key=key):
                self.assertRegex(it, rf"\n\s+{key}:")
                self.assertRegex(en, rf"\n\s+{key}:")

    def test_no_inline_handlers_in_the_new_modals(self):
        start = self.html.index('id="bpAssistantModal"')
        end = self.html.index("<!-- Which location of an organization")
        self.assertNotRegex(self.html[start:end], r"\bon[a-z]+=")
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_blueprint_tab.py -k Assistant -v`
Expected: FAIL — `btnBpAssistant` not in the template.

- [ ] **Step 3: Markup** — `templates/dashboard.html`.

In the Blueprint bar, right after the `btnBpHistory` button:

```html
          <button type="button" class="btn btn-secondary btn-small" id="btnBpAssistant"><i class="fa-solid fa-wand-magic-sparkles" aria-hidden="true"></i> <span data-i18n="btnBpAssistant">Assistente</span></button>
          <button type="button" class="btn btn-secondary btn-small" id="btnBpInstructions" data-i18n="btnBpInstructions">Istruzioni assistente</button>
```

Right before `<!-- Which location of an organization (pickLocation, core.js). -->`:

```html
  <div class="modal-overlay" id="bpAssistantModal">
    <div class="modal" style="width: 620px; max-width: 95%;">
      <div class="modal-header">
        <h3><i class="fa-solid fa-wand-magic-sparkles"></i> <span data-i18n="bpAssistModalTitle">Assistente Blueprint</span></h3>
        <button type="button" class="modal-close" data-close-modal="bpAssistantModal" aria-label="Chiudi" data-i18n-aria-label="btnClose"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <p class="form-hint" data-i18n="bpAssistHint">Le proposte finiscono nella bozza: nulla cambia finché non la applichi.</p>
      <section class="bp-assist-pane">
        <h4 data-i18n="bpAssistDescribeTitle">Descrivi la rete</h4>
        <div class="form-group">
          <label for="bpAssistText" data-i18n="lblBpAssistText">Descrizione (massimo 4000 caratteri)</label>
          <textarea id="bpAssistText" rows="5" maxlength="4000" data-i18n-placeholder="bpAssistTextPh" placeholder="Sede centrale a Milano con 10.10.0.0/16, filiali a Roma e Torino collegate in VPN" style="width:100%; font-size:13px; padding:8px;"></textarea>
        </div>
        <button type="button" class="btn btn-primary btn-small" id="btnBpAssistDescribe" data-i18n="btnBpAssistDescribe">Genera bozza</button>
      </section>
      <section class="bp-assist-pane">
        <h4 data-i18n="bpAssistDeriveTitle">Dalle configurazioni</h4>
        <p class="form-hint" data-i18n="bpAssistDeriveHint">Legge i backup degli apparati: subnet delle interfacce, gateway con la rotta di default, VPN IPsec FortiGate tra sedi.</p>
        <div class="form-group">
          <input type="checkbox" id="bpAssistUseAi">
          <label for="bpAssistUseAi" data-i18n="lblBpAssistUseAi">Usa l'AI per nomi e ruoli</label>
        </div>
        <button type="button" class="btn btn-primary btn-small" id="btnBpAssistDerive" data-i18n="btnBpAssistDerive">Ricava</button>
      </section>
      <p id="bpAssistError" class="form-hint" role="alert" style="color:var(--danger);"></p>
      <pre id="bpAssistNotes" class="bp-assist-notes" hidden></pre>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" data-close-modal="bpAssistantModal" data-i18n="btnClose">Chiudi</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="bpInstructionsModal">
    <div class="modal" style="width: 560px; max-width: 95%;">
      <div class="modal-header">
        <h3><i class="fa-solid fa-book"></i> <span data-i18n="bpInstrModalTitle">Istruzioni assistente</span></h3>
        <button type="button" class="modal-close" data-close-modal="bpInstructionsModal" aria-label="Chiudi" data-i18n-aria-label="btnClose"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <p class="form-hint" data-i18n="bpInstrHint">Convenzioni di questa organizzazione che l'assistente segue: nomi delle sedi, piano di indirizzamento, ruoli.</p>
      <div class="form-group">
        <label for="bpInstrText" data-i18n="lblBpInstrText">Istruzioni (massimo 4000 caratteri)</label>
        <textarea id="bpInstrText" rows="8" maxlength="4000" style="width:100%; font-size:13px; padding:8px;"></textarea>
      </div>
      <p id="bpInstrError" class="form-hint" role="alert" style="color:var(--danger);"></p>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" data-close-modal="bpInstructionsModal" data-i18n="uiCancel">Annulla</button>
        <button type="button" class="btn btn-primary" id="btnBpInstrSave" data-i18n="uiSave">Salva</button>
      </div>
    </div>
  </div>
```

- [ ] **Step 4: Module** — `static/js/blueprint.js`.

In `renderDraftOps`, the list item gets the source tag:

```js
    function renderDraftOps() {
        $('bpDraftOps').innerHTML = draftOps().map((op, i) => `<li>${describeOp(op)}
            ${op.source === 'assistant' ? `<span class="bp-draft-tag">${escapeHtml(tr('bpOpFromAssistant'))}</span>` : ''}
            ${EDITABLE.includes(op.op) ? `<button type="button" class="bp-link-btn" data-action="bp-op-edit" data-i="${i}">${escapeHtml(tr('btnBpEditOp'))}</button>` : ''}
            <button type="button" class="bp-link-btn danger" data-action="bp-op-remove" data-i="${i}">${escapeHtml(tr('btnBpRemoveOp'))}</button></li>`).join('');
    }
```

Before `// ---- bindings (the module loads once, with its tab) ----`:

```js
    // ---- assistant (spec 2026-10-11 blueprint-assistant) ---------------------
    // Both entry points only append to the draft; the draft bar takes it from there.

    function openAssistant() {
        $('bpAssistError').textContent = '';
        $('bpAssistNotes').hidden = true;
        $('bpAssistUseAi').disabled = !bpState.ai_available;
        if (!bpState.ai_available) $('bpAssistUseAi').checked = false;
        openModal('bpAssistantModal');
    }

    async function runAssistant(path, body, btn) {
        btn.disabled = true;
        $('bpAssistError').textContent = '';
        $('bpAssistNotes').hidden = true;
        try {
            const res = await send(path, 'POST', body);
            if (!res || !res.ok) { $('bpAssistError').textContent = await errorText(res); return; }
            const out = await res.json();
            showToast(tr('bpAddedToDraft', { n: out.added }), 'success');
            $('bpAssistNotes').textContent = out.notes || '';
            $('bpAssistNotes').hidden = !out.notes;
            await reloadBlueprint();
        } finally {
            btn.disabled = false;
        }
    }

    function openInstructions() {
        $('bpInstrText').value = bpState.instructions || '';
        $('bpInstrError').textContent = '';
        openModal('bpInstructionsModal');
    }

    async function saveInstructions() {
        const res = await send('/instructions', 'PUT', { text: $('bpInstrText').value });
        if (!res || !res.ok) { $('bpInstrError').textContent = await errorText(res); return; }
        bpState.instructions = (await res.json()).instructions;
        closeModal('bpInstructionsModal');
        showToast(tr('bpInstrSaved'), 'success');
    }
```

In the bindings, after `$('btnBpDiff').addEventListener('click', compare);`:

```js
    $('btnBpAssistant').addEventListener('click', openAssistant);
    $('btnBpInstructions').addEventListener('click', openInstructions);
    $('btnBpAssistDescribe').addEventListener('click', () =>
        runAssistant('/assistant/describe', { text: $('bpAssistText').value }, $('btnBpAssistDescribe')));
    $('btnBpAssistDerive').addEventListener('click', () =>
        runAssistant('/assistant/derive', { use_ai: $('bpAssistUseAi').checked }, $('btnBpAssistDerive')));
    $('btnBpInstrSave').addEventListener('click', saveInstructions);
```

- [ ] **Step 5: Strings** — `static/js/i18n.js`, after `bpObserved: "Dati raccolti da {n} gateway.",` in `it`:

```js
        // Blueprint assistant (blueprint.js, spec 2026-10-11 blueprint-assistant)
        btnBpAssistant: "Assistente",
        btnBpInstructions: "Istruzioni assistente",
        bpAssistModalTitle: "Assistente Blueprint",
        bpAssistHint: "Le proposte finiscono nella bozza: nulla cambia finché non la applichi.",
        bpAssistDescribeTitle: "Descrivi la rete",
        lblBpAssistText: "Descrizione (massimo 4000 caratteri)",
        bpAssistTextPh: "Sede centrale a Milano con 10.10.0.0/16, filiali a Roma e Torino collegate in VPN",
        btnBpAssistDescribe: "Genera bozza",
        bpAssistDeriveTitle: "Dalle configurazioni",
        bpAssistDeriveHint: "Legge i backup degli apparati: subnet delle interfacce, gateway con la rotta di default, VPN IPsec FortiGate tra sedi.",
        lblBpAssistUseAi: "Usa l'AI per nomi e ruoli",
        btnBpAssistDerive: "Ricava",
        bpInstrModalTitle: "Istruzioni assistente",
        bpInstrHint: "Convenzioni di questa organizzazione che l'assistente segue: nomi delle sedi, piano di indirizzamento, ruoli.",
        lblBpInstrText: "Istruzioni (massimo 4000 caratteri)",
        bpInstrSaved: "Istruzioni salvate.",
        bpOpFromAssistant: "assistente",
```

and after `bpObserved: "Data collected from {n} gateways.",` in `en`:

```js
        // Blueprint assistant (blueprint.js, spec 2026-10-11 blueprint-assistant)
        btnBpAssistant: "Assistant",
        btnBpInstructions: "Assistant instructions",
        bpAssistModalTitle: "Blueprint assistant",
        bpAssistHint: "Proposals go into the draft: nothing changes until you apply it.",
        bpAssistDescribeTitle: "Describe the network",
        lblBpAssistText: "Description (up to 4000 characters)",
        bpAssistTextPh: "Head office in Milan with 10.10.0.0/16, branches in Rome and Turin connected by VPN",
        btnBpAssistDescribe: "Generate draft",
        bpAssistDeriveTitle: "From configurations",
        bpAssistDeriveHint: "Reads the device backups: interface subnets, the gateway holding the default route, FortiGate IPsec VPNs between locations.",
        lblBpAssistUseAi: "Use AI for names and roles",
        btnBpAssistDerive: "Derive",
        bpInstrModalTitle: "Assistant instructions",
        bpInstrHint: "Conventions of this organization the assistant follows: location names, addressing plan, roles.",
        lblBpInstrText: "Instructions (up to 4000 characters)",
        bpInstrSaved: "Instructions saved.",
        bpOpFromAssistant: "assistant",
```

- [ ] **Step 6: Styles** — append to `static/css/dashboard.css` after the Blueprint block:

```css
/* Blueprint assistant (blueprint.js) */
.bp-assist-pane { margin: 14px 0 0; padding-top: 10px; border-top: 1px solid var(--border); }
.bp-assist-pane h4 { margin: 0 0 8px; }
.bp-assist-notes { white-space: pre-wrap; margin: 10px 0 0; padding: 8px; font-size: 12px; border: 1px solid var(--border); }
```

- [ ] **Step 7: Run tests and checks**

Run:
```bash
uv run pytest tests/test_blueprint_tab.py tests/test_lazy_tab_scripts.py tests/test_ui_modal.py tests/test_i18n_keys.py tests/test_i18n_parity.py tests/test_a11y_dashboard.py -v
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
```
Expected: all PASS / zero findings. If `check_frontend` (tsc) complains about `.checked`/`.disabled` on the `$()` result, follow how the module already reads `.value` on `$()` results (the same helper), not a cast per line.

- [ ] **Step 8: Run it** — `uv run python app_server.py`, log in as admin, open «Blueprint di rete», pick an organization. «Istruzioni assistente» → type a line → «Salva» → reopen: the text is there. «Assistente»: with no AI profile active the checkbox is disabled; «Genera bozza» shows the «Nessun profilo AI…» message in the modal. «Ricava» on an organization whose devices have no backup shows «Nessuna proposta dalle configurazioni…»; with backups it toasts «N modifiche aggiunte alla bozza.», the draft bar appears, «Rivedi» lists the ops tagged «assistente». The browser console shows no error.

- [ ] **Step 9: Gate and commit**

```bash
uv run pyrefly check && uv run python scripts/check_frontend.py && uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add templates/dashboard.html static/js/blueprint.js static/js/i18n.js static/css/dashboard.css tests/test_blueprint_tab.py
git commit -m "feat(blueprint): assistant and instructions modals in the Blueprint tab"
```

---

### Task 9: Docs, screenshots, graph

**Model:** sonnet

**Files:**
- Modify: `docs/network-blueprint.md` (new section before «## Primi passi»), `docs/README.md` (row of `network-blueprint.md`), `docs/hardening.md` (§7), `README.md` (MCP consent paragraph)
- Regenerate: `docs/images/` via `scripts/dev/capture_screenshots.py` (the Blueprint bar gained two buttons)

- [ ] **Step 1: `docs/network-blueprint.md`** — insert before `## Primi passi`:

```markdown
## Assistant

Three ways to fill the draft without typing every operation. All three only
**append to the draft**, with source `assistant` (shown as «assistente» in
«Rivedi»): applying stays the admin's «Applica».

- **«Descrivi la rete»** (button «Assistente»): write the network in a sentence —
  «sede centrale a Milano con 10.10.0.0/16, filiali a Roma e Torino in VPN» — and
  «Genera bozza». The active AI profile (AI tab) turns it into operations; an
  answer that does not validate is sent back once with the error, then refused.
  Needs an active AI profile; with Ollama nothing leaves the server.
- **«Ricava dalle configurazioni»**: reads the latest backup of every device of
  the organization, no AI needed. It proposes each private interface network
  (not /31–/32, not loopbacks, not shut down) that no location covers yet, to the
  device's location; the gateway of a location without one when exactly one of
  its devices has a static default route (outside VRFs); a `vpn` link when a
  FortiGate phase 1 points (`remote-gw`) at a device of another location. Devices
  without a location or a backup are listed in the notes. «Usa l'AI per nomi e
  ruoli» adds a second, optional pass that may only rename locations or change
  their role; if it fails, the derived operations stay.
- **MCP** (`blueprint_get`, `blueprint_propose`): an external client can read the
  model with its checks and propose operations. It needs an admin account, or a
  read-only sign-in where the admin ticked «Consenti di proporre bozze del
  Blueprint» on the consent page; the right ends when the user stops being an
  admin.

**«Istruzioni assistente»** holds the organization's conventions (location
names, addressing plan, roles), up to 4000 characters, sent with every
«Descrivi» and AI pass. They are not part of the revisions.

The description, the model and the instructions reach the AI provider only when
you press a button, through the active profile, as in the AI tab.
```

- [ ] **Step 2: Index row** — `docs/README.md`, the `network-blueprint.md` row becomes:

```markdown
| [network-blueprint.md](network-blueprint.md) | Network Blueprint: expected network per organization (locations, links, gateways), drafts, revisions and restore, presets, deterministic checks against observed routes, ARP and IPsec tunnels, assistant (from text, from config backups, from MCP) |
```

- [ ] **Step 3: `docs/hardening.md` §7**
  - Replace `exposes 59 tools` with the number printed by `uv run python -c "from ai import mcp_server; print(len(mcp_server.TOOLS))"`.
  - In the «Read-only, safe to enable» row, append `` `blueprint_get` `` to the tool list (after `` `get_device_classification` ``).
  - Add a row after «Touches devices — enable deliberately»:

```markdown
| **Writes a draft only** | `blueprint_propose` | Appends operations to an organization's Blueprint draft; nothing is applied until an admin presses «Applica». Needs an admin account, or a read-only grant on which the admin ticked «Consenti di proporre bozze del Blueprint» (`bpd` claim, re-checked against the user's current role at every call) |
```

- [ ] **Step 4: `README.md`** — in the MCP consent paragraph, after the sentence ending `so the model cannot run commands.`, add:

```markdown
An admin who keeps **Read-only** can also tick **Allow proposing Blueprint
drafts**: the client may then call `blueprint_propose`, which only appends
operations to an organization's Blueprint draft for an admin to review.
```

- [ ] **Step 5: Screenshots and graph**

```bash
uv run python scripts/dev/capture_screenshots.py
graphify update .
```

If `graphify update .` refuses with «fewer nodes», do not pass `--force` before checking what shrank (AGENTS.md).

- [ ] **Step 6: Gate and commit**

```bash
uv run pytest tests -n 4 && uv run python scripts/check_no_private_data.py
git add docs/network-blueprint.md docs/README.md docs/hardening.md README.md docs/images
git commit -m "docs(blueprint): assistant guide, MCP draft permission, screenshots"
```

---

## Self-review

- **Spec coverage.** «Descrivi la rete» → Task 4 (`describe`, retry, limits) + Task 5 (route) + Task 8 (UI). «Ricava» → Task 2 (phase-1 peers), Task 3 (pure derive), Task 4 (gathering, AI pass), Task 5 (route), Task 8 (UI). Organization instructions → Task 1 (column), Task 4 (`state.instructions`, prompts), Task 5 (PUT), Task 8 (modal). MCP → Task 6 (consent checkbox, grant, `bpd`, `assistant-draft`), Task 7 (tools). UI (`ai_available`, toast, notes, source in draft review, `tr()`, `openModal`, named controls) → Task 8. Errors and privacy (AI error codes, audit with op count per call) → Tasks 4–6, adjustment 1. Testing section → every listed case has a test: derive cases (Task 3), `config_analyzer` (Task 2), describe cases (Task 4), AI pass (Task 4), `assistant-draft` gates (Task 6), MCP session (Task 6), instructions (Tasks 1, 4, 5), UI wiring (Task 8). Docs → Task 9.
- **Placeholder scan.** No TBD/TODO; every code step carries its code; the hardening tool count is computed by a given command.
- **Type consistency.** `derive(view, devices, analyses) -> (ops, notes)` (Task 3) is what Task 4 calls; `describe/derive -> {"added", "notes", "state"}` is what Tasks 5 and 8 read; `set_instructions(org, text) -> str` matches the router; `create_code(..., bp_draft=False)` and `user_for_grant -> {"user", "read_only", "bp_draft"}` match `routers/mcp.py`; route paths `/assistant/describe`, `/assistant/derive`, `/instructions`, `/assistant-draft` are the same in Tasks 5–8; schema names in `test_router_parity` match the router.
- **Review Focus.** Each of the five lines has its test in the owning task (names listed in the section).

## After this plan

Sub-project 5 (maps and routing per location) reads `inventory_store.read_links` and may reuse `blueprint_derive`'s interface reading. Version bump at release time (`scripts/dev/release.py`, MINOR: new feature).
