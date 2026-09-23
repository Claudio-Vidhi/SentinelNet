# Site wizard (bastion creation) — design (2026-09-23)

First of three pieces of the provisioning UX revamp. The other two — adding a
device, and Zero-Touch provisioning — get their own specs and reuse the panel
component this piece introduces.

## Problem

Creating a site is one flat modal (`createSiteModal`). Picking "Jump" in a
select reveals four more fields and a callout listing what does not work on a
jump site — *after* the mode was chosen. Nothing is verified: the site is saved
without ever dialing the bastion, and the first sign of a wrong host or
credential is a device row failing later. On first contact the bastion's SSH
host key is pinned silently (`core/net_ssh.py` `_dial`, trust on first use),
so nobody ever looks at it. Editing is a second modal, and the agent enrollment
instructions a third.

Pain points named by the user: dated/inconsistent look, no feedback or
validation, modes hard to understand, too many fields at once.

## References (Mobbin)

- Mode cards beside a step rail — [Cloudflare Hyperdrive](https://mobbin.com/screens/e3d549ce-6d56-4ea7-9057-51fdf69d1b70)
- Test and save with the raw error and a Retry — [Steep, connect a data source](https://mobbin.com/flows/58e0b2a3-c944-482f-acb8-f8a0fc6a3e9d)
- Testing → success states inside a side panel — [Zapier, testing a connection](https://mobbin.com/flows/fcd35efa-2b51-4de9-8999-e1ba024d075c)

## Decisions

| Question | Decision |
|---|---|
| Shape of the flow | Right-hand side panel with a step rail (not a modal form, not a full page) |
| Host key on first contact | Shown as `SHA256:` fingerprint; the operator confirms it before it is pinned |
| Failed or skipped test | Site may still be saved; marked "Not verified" until a test passes |

## Flow

The panel has four steps: **Mode → Details → Connection → Summary**.

1. **Mode.** Three cards (central poll, site agent, jump SSH), each listing what
   works (✓) and what does not (✗). The jump card carries the content of
   today's `jumpLimits` callout.
2. **Details.** Name; subnets as chips, each validated as CIDR while typing.
   For jump: bastion host, port, bastion identity (with a "+ new identity"
   link), default device identity (optional, one line explaining it is a
   different credential from the bastion's).
3. **Connection**, per mode:
   - *jump*: "Test connection" button. Outcomes, rendered in an `aria-live`
     region: testing; success with the host-key fingerprint and a required
     checkbox "this is my bastion's fingerprint"; bastion login refused
     (worded as the bastion credential, not a device's); unreachable (raw
     error + Retry); host key differs from the recorded one. "Save without
     verifying" remains available, with a warning.
   - *agent*: shown **after** saving. The enrollment config and commands with
     a Copy button, and a live indicator that turns green on the first
     heartbeat. Replaces `siteEnrollModal`.
   - *central*: nothing to test; the step is skipped.
4. **Summary.** Read-only recap, then Save.

Editing opens the same panel at step 2; every step is clickable in edit mode,
and changing the mode warns about the consequences (today's
`editSiteModeWarning`).

Sites table: a jump site without a successful test shows a **Not verified**
badge beside its agent status.

## Backend

### Test before saving

`POST /api/sites/test-bastion/draft`, body `{jump_host, jump_port,
jump_identity}`, `require_unscoped_admin`, tab `tab-sites`.

- `_dial(site, pin=True)` gains the `pin` parameter; the draft test calls it
  with `pin=False` on a site dict built from the draft fields, reads
  `tr.get_remote_server_key()` and closes the transport. `probe_bastion()`
  keeps its behaviour.
- Response `{status, message, fingerprint, key_type, known}`; `status` is
  `success | auth_failed | unreachable | host_key_mismatch`; `known` is true
  when this key is already pinned for `(host, port)`.
- The key seen is kept in process memory for 10 minutes, keyed by
  `(host, port)`.

### Confirming the fingerprint

`SiteSchema` and `SiteUpdateSchema` gain `confirmed_fingerprint:
Optional[str]`. On create/update, when present:

- it must equal the fingerprint of the cached key for the site's
  `(jump_host, jump_port)`; then the server pins that key
  (`_pin_host_key`) and sets `bastion_verified_ts = now`;
- cache expired or fingerprint different → HTTP 409, "test again".

The browser never sends key material, only the fingerprint the operator
confirmed; the server checks it against the key it saw itself.

### Verified flag

- New site field `bastion_verified_ts` (null by default), returned by
  `GET /api/sites` to unscoped admins.
- Cleared by `update_site` when `jump_host`, `jump_port` or `jump_identity`
  change without a matching `confirmed_fingerprint`.
- The existing `POST /api/sites/test-bastion` sets it on success and also
  returns the fingerprint.
- An unverified site keeps today's behaviour: the first real dial pins the key
  (TOFU). The badge is what makes that visible.

### Agent heartbeat indicator

No new endpoint: while the enrollment step is visible the panel polls
`GET /api/sites` every 5 s and watches the site's `last_seen`.

### Audit

`log_audit` entries for: draft test (with outcome), fingerprint confirmed and
pinned, site saved unverified.

## Frontend

### `static/js/ui-wizard.js` (shared)

Loaded eagerly after `ui-modal.js`, because pieces 2 and 3 use it.

```js
const wiz = createWizard('siteWizard', {
  steps: [
    { id: 'mode',    validate, onEnter },
    { id: 'details', validate, onEnter },
    { id: 'connect', validate, onEnter, skip },   // skip() true for central
    { id: 'summary', onEnter },
  ],
  onFinish,
});
wiz.open({ at: 'details', editable: true });   // edit mode
```

- Each step is a `<section data-step="…">` inside the panel; the rail is
  rendered from the step list.
- **Next** is disabled until the current step's `validate()` is true.
- In edit mode every rail item is a button.
- Open/close, focus trap and Esc come from `openModal` / `closeModal`.
- Exposed as `window.createWizard`, declared in `types/globals.d.ts`.

### Styles (`static/css/dashboard.css`)

- `.modal.sheet`: right-hand panel; full width below 720px.
- `.choice-card`: mode cards built on real `<input type="radio">` inside a
  `role="radiogroup"`, so keyboard and screen readers work unchanged.
- Fingerprint in the monospace token.
- Existing tokens only, square corners (DESIGN.md), no new inline `style=`.

### Template and `settings.js`

`createSiteModal`, `editSiteModal` and `siteEnrollModal` are replaced by one
`siteWizard` sheet. The site code in `settings.js` (create, edit, enrollment,
test) is rewritten on top of the wizard; `loadSites()` renders the badge.

### i18n and accessibility

- Every new string has IT and EN keys; keys left unused are removed.
- Every control has a label; the test outcome is in an `aria-live` region.

## Testing

- **Backend (pytest), `_dial` mocked:** each draft-test outcome; matching
  fingerprint pins the key and sets `bastion_verified_ts`; expired or
  different fingerprint → 409; changing the host clears the flag; scoped admin
  → 403; audit entries written; `probe_bastion()` still pins as before.
- **Frontend:** node harness for `ui-wizard.js` — Next blocked by a failing
  `validate()`, `skip()` honoured, rail clickable only in edit mode.
- **Gates:** `check_frontend.py`, `check_a11y.py --strict`,
  `check_i18n_coverage.py --strict`, `test_ui_modal.py`,
  `test_lazy_tab_scripts.py`, full suite.
- **Visual:** screenshots through the Chrome MCP after the user logs in.

## Out of scope

- Adding a device (piece 2) and Zero-Touch provisioning (piece 3).
- Changing TOFU for unverified sites.
- Removing a pinned key from the UI (still a manual `ssh_known_hosts` edit).
