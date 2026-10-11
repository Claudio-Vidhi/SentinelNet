# Blueprint assistant — drafts from text, from configurations, from MCP (2026-10-11)

Sub-project 4 of the multi-location revamp
([roadmap](2026-10-09-organizations-locations-design.md)). Builds on the
Network Blueprint ([spec](2026-10-11-network-blueprint-design.md)): every
output of this sub-project is a set of **draft operations** appended through
`blueprint.add_ops(org, ops, "assistant", by)`. Nothing here writes the model;
applying stays a human action in the Blueprint tab.

## Problem

Filling the Blueprint by hand is slow for an organization with many
locations. The operator can describe the network in a sentence, and the
configuration backups SentinelNet already keeps say most of it (interface
subnets, default routes, IPsec peers). External AI clients connected over MCP
should be able to propose a model too — without gaining write access to
anything else.

## Decisions

| Question | Decision |
|---|---|
| Entry points | «Descrivi la rete» (text → draft), «Ricava dalle configurazioni» (backups → draft), MCP tool (client → draft). |
| LLM | The active AI profile (`routers/ai.chat_with_active_profile`). No new provider code. |
| «Ricava» | Deterministic extraction; an optional LLM pass may only rename locations or change their role. Works with no AI profile. |
| Validation | Every op goes through `apply_ops` (via `add_ops`); an invalid LLM answer gets one retry with the error, then a 422. |
| Custom instructions | Per organization (`organizations.assistant_instructions`), not per AI profile. |
| MCP write | A read-only (`ro`) grant can carry one extra permission, `bp_draft`, granted on the consent page only to admins. It opens one endpoint that appends ops with source `assistant`. Grants with the full role already reach the normal draft route. |
| Apply | Never from the assistant or MCP. |

## «Descrivi la rete» — `blueprint_assistant.describe(org, text, by)`

- Messages for `chat_with_active_profile`:
  - system: role, the JSON schema of the seven operations (fields, enums,
    `+ref` rule, `add_link` endpoints may be ids or refs), the rules (only this
    organization, never delete unless the text asks for it, subnets in CIDR),
    the organization's instructions, and the reply format
    `{"ops": [...], "notes": "..."}` with no prose around it;
  - user: the current model of the organization (preview if a draft exists:
    locations with id, name, role, subnets, gateway; links) as JSON, then the
    operator's text.
- Parse: the first JSON object in the reply (code fences tolerated). Not JSON,
  no `ops` list, or an `OpError` from `add_ops` → one retry, appending the
  assistant reply and a user message with the error (operation index within the reply, and
  message). Second failure → `ValueError` (422) carrying the last error.
- Success → `add_ops(org, ops, "assistant", by)`; returns
  `{"added": n, "notes": str, "state": state(org)}`.
- Text limit 4000 characters; empty text → 422.
- Route: `POST /api/blueprint/{org}/assistant/describe` `{text}` (admin).

## «Ricava dalle configurazioni» — `blueprint_derive.derive(view, devices, analyses)`

Pure module. `analyses` maps device IP → `config_analyzer.analyze_device(ip, org)`
result (or `None` when there is no backup). Output `(ops, notes)`.

- `add_subnet`: each interface address with a mask (IOS and FortiOS parsers
  already give it), RFC 1918, prefix shorter than /31, not a loopback, whose
  network no location of the organization covers yet → its network goes to the
  device's location. One op per (location, network). Interfaces administratively down are skipped; a network that overlaps a location subnet counts as covered; a network seen in two locations goes to the first location by id. IPv4 only.
- `set_gateway`: a location with no gateway where exactly one of its devices
  has a static default route (`0.0.0.0/0`, outside any VRF) in its backup → that device; more than one candidate → a note, no op.
- `add_link vpn`: a FortiOS `vpn ipsec phase1-interface` whose `remote-gw` is
  the inventory IP, or an interface address in the backup, of a device in another location of the same organization, the two
  locations not already linked by a `vpn` link. One op per pair.
  `config_analyzer` today records only phase-1 names; it gains
  `vpn.peers`, one `{"name", "remote_gw"}` per phase 1 (FortiOS only); `vpn.phase1` stays the list of names its readers expect.
- Skipped and counted in `notes`: devices without a location, without a
  backup, with an unparsable backup.
- Optional LLM pass (checkbox «Usa l'AI per nomi e ruoli», only when an AI
  profile is active): given the model and the derived ops, the LLM may answer
  `update_location` ops touching only `name` and `role`; any other op type or
  field is dropped before validation, and the pass failing never loses the
  deterministic ops (they are appended first).
- `blueprint_assistant.derive(org, by, use_ai)` reads devices and analyses,
  calls the pure function, appends, returns `{"added", "notes", "state"}`. No
  ops → 422 «Nessuna proposta dalle configurazioni» with the notes.
- Route: `POST /api/blueprint/{org}/assistant/derive` `{use_ai}` (admin).

## Organization instructions

- `organizations` gains `assistant_instructions TEXT NOT NULL DEFAULT ''`
  (ALTER for existing databases, as `locations.gateway`).
- `GET` is part of `state(org)` (`instructions`); `PUT
  /api/blueprint/{org}/instructions` `{text}` (admin, ≤ 4000 characters).
- Not part of revisions: they describe conventions, not the network.

## MCP

- Consent page (`/mcp/authorize`): with «sola lettura» selected and the user an
  admin, a checkbox «Consenti di proporre bozze del Blueprint». The grant
  (`security/mcp_grants`) stores `bp_draft: bool` next to `read_only`.
- `/api/mcp/session`: a read-only grant with `bp_draft` whose user is **still**
  an admin at session time gets claim `bpd: true` besides `ro`.
- `assistant-draft` re-reads the user's role at every call: a user demoted after the session opened is refused at once.
- `POST /api/blueprint/{org}/assistant-draft` `{ops, note}`:
  `require_tab("tab-blueprint")`, `assert_group_allowed`, and the caller is
  either an admin session or a session with `ro` + `bpd`. Source forced to
  `assistant`; the note is stored in the audit entry. Only appends — the route
  exposes no preset, restore, apply, discard, align.
- MCP tools (`ai/mcp_server.py`):
  - `blueprint_get(org)` → `GET /api/blueprint/{org}` and `/checks`;
  - `blueprint_propose(org, ops, note)` → `assistant-draft`. Listed like every
    other tool (the operator's tool-config can disable it); a client without
    the permission gets the 403 message.

## UI (Blueprint tab)

- «Assistente» button → modal with two panes:
  - «Descrivi»: textarea, «Genera bozza»;
  - «Dalle configurazioni»: checkbox «Usa l'AI per nomi e ruoli» (disabled
    when no AI profile is active; `state` gains `ai_available`), «Ricava».
- Result: toast «N modifiche aggiunte alla bozza», the notes in the modal, the
  draft bar and lists refresh. Operations from the assistant show their source
  in the draft review.
- «Istruzioni assistente» button → modal with a textarea, saved with the PUT.
- Strings via `tr()`, both languages; modals via `openModal`; named controls.

## Errors and privacy

- No active AI profile (or no API key) → 400, provider errors → 502 with the `AiAssistantError` message, rate limit → 429: the codes `routers/ai.chat_with_active_profile` already returns to the AI tab and the classification assistant. For derive, the AI pass is just skipped.
- Network data reaches the LLM only on an explicit action, through the active
  profile, as in the AI tab today; with Ollama it stays local.
- Audit: each describe/derive/assistant-draft call, with the op count.

## Testing

- `blueprint_derive`: synthetic IOS and FortiOS analyses → expected ops;
  covered networks, public addresses, /32, loopbacks skipped; one default-route
  candidate vs two; phase-1 `remote-gw` to another location, to the same
  location, to an unknown IP; notes for skipped devices.
- `config_analyzer`: FortiOS phase1 `remote-gw` parsed.
- `describe` with a fake `chat`: valid JSON; fenced JSON; invalid then valid
  (one retry, error message sent back); invalid twice → 422; op error on retry.
- derive AI pass: non-`update_location` ops and fields other than name/role
  dropped; AI failure keeps the deterministic ops.
- `assistant-draft`: admin OK; `ro` without `bpd` 403; `ro` + `bpd` with the
  user demoted 403; other tenant 403; viewer 403.
- MCP session: `bpd` only for read-only + `bp_draft` + admin.
- Instructions: PUT/GET round trip, length limit, included in the prompt.
- UI: `test_blueprint_tab`-style wiring, i18n, a11y.

## Out of scope

Maps and routing per location (5); applying drafts from MCP or the assistant;
non-FortiOS IPsec peers; per-AI-profile prompts.
