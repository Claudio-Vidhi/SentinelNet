# Remote-site security and management findings

Review of `remote_site_summary.md` and the current Mode B implementation.

## Verdict

Yes: **remote-agent security and remote-device management should be separate
planes**.  They cooperate, but they answer different questions and should not
share an all-or-nothing authority boundary:

| Plane | Principal | Primary responsibility | Should not grant |
| --- | --- | --- | --- |
| Agent/control plane | The registered site agent | Prove agent identity, deliver work, report health, inventory and results | Unrestricted access to every device or every possible action |
| Device/data plane | A device identity and its credential/policy | Connect to, observe and change one device | Authority to impersonate the agent, create jobs, or administer Central |

The existing design already makes a useful first separation: Central authenticates
the site agent with a per-site token, while device credentials remain in the
agent's local data directory.  This limits credential exfiltration from a
compromised Central server.  It is not yet a complete separation of authority:
the authenticated agent currently receives all pending jobs for its site and
executes them using whichever local device record has the requested IP.

## What is sound today

- The agent initiates outbound HTTPS only; Central does not need inbound access
  to the remote network.
- The `/api/agent/*` endpoints use a different credential from Central user
  sessions.  Tokens are stored server-side only as SHA-256 hashes, compared with
  `secrets.compare_digest`, and are scoped to one `site_id`.
- Job completion verifies the job's site before accepting a result, preventing
  one valid site agent from completing another site's job.
- The agent transmits inventory metadata, not the username/password/enable
  fields.  The local inventory code encrypts password and enable-secret fields
  with Fernet at rest; this is stronger and more accurate than describing the
  CSV simply as plaintext credential storage.
- Central users must be operators or admins to queue site commands, and the
  command blacklist is applied before a job is queued.

## Important limits and corrections to the summary

1. **A site token is an agent identity, not device-level authorization.**  A
   compromised agent can poll every queued command for its site, run it locally,
   and submit fabricated results, inventory, or MAC sightings.  Token rotation
   stops future Central API use, but cannot undo commands already obtained or
   protect devices reachable with credentials already present on the VM.
2. **The local VM remains a high-value credential boundary.**  Fernet protects
   the CSV at rest only if the corresponding local `secret.key`/master key and
   process account are protected.  The normal `agent.json` configuration also
   contains the bearer site token; permissions, OS hardening and secret storage
   matter.
3. **"Central receives metadata only" needs a qualification.**  Command output
   is posted back to Central and can contain configuration, topology, or secret
   material.  Inventory/MAC data are also centrally persisted.  Result
   redaction, retention and access control therefore belong in the model.
4. **Command authorization is broad.**  The relay accepts any syntactically
   valid IP for an agent site; the agent rejects it only when it is absent from
   its local inventory.  There is no Central-side per-device entitlement,
   command approval policy, or cryptographic binding of a job to an approved
   device identity.
5. **Poll/claim reliability needs an explicit recovery policy.**  A job moves
   from `pending` to `running` when polled.  There is no visible lease expiry or
   retry/reconciliation for an agent that crashes after claiming it.  This is a
   management concern, but it becomes security-relevant during incident
   response and token rotation.

## Recommended target model

Keep one deployment/ownership model for a site, but make the planes explicit:

1. **Agent lifecycle and trust:** enrollment, mTLS certificate (or a rotated
   short-lived token as an interim step), attestation/version/health state,
   revocation, and an immutable agent audit trail.  Treat token rotation as
   containment, not proof that devices are safe.
2. **Device lifecycle and policy:** inventory identity (prefer stable device ID
   or certificate/fingerprint over IP alone), credential reference, allowed
   transport, least-privilege device account, approved command classes, and
   owner/tenant/site tags.
3. **A signed, constrained job envelope:** Central should send `job_id`, site,
   device ID, command/request type, requester, expiry, policy decision and a
   nonce.  The agent verifies the envelope and executes only if the locally
   discovered device matches the approved identity and policy.  Results should
   include an execution receipt and redaction marker.
4. **Separate RBAC:** management of sites/agent enrollment, management of
   device credentials, and permission to execute/read commands should be
   distinct grants.  A network operator should not automatically be able to
   rotate agents or edit credentials, and an agent administrator should not
   automatically be able to run destructive commands.

## Practical next steps (priority order)

1. Document the corrected threat boundaries above in `remote_site_summary.md`,
   especially the limits of token rotation and the sensitivity of command
   results.
2. Add job leases, expiry, idempotency/retry semantics and an incident state
   (`disabled`/`quarantined`) for agents; stop dispatch while a site is
   quarantined.
3. Bind jobs to a centrally known device record and validate site, inventory
   membership and a stable device fingerprint on the agent.  Add per-device
   command allowlists/approval for changes before allowing broad relay use.
4. Move the site token and encryption key out of ordinary configuration files
   into an OS secret store or service-account protected store; restrict file
   permissions and run the agent as a dedicated low-privilege account.
5. Replace the long-lived bearer token with per-agent mTLS and short-lived
   workload credentials when the enrollment/rotation workflow is ready.

## Checkmk comparison

Checkmk provides a useful operational analogy: its distributed monitoring sites
are managed as separate monitored instances, while the hosts/devices within a
site have their own monitoring configuration, credentials and permissions.
SentinelNet should use the same conceptual split.  Central must be able to
manage the *agent/site as a workload* (enrollment, health, software version,
revocation) without treating that authority as permission to manage every
device.  Conversely, device policy and credentials should constrain what a
healthy agent may do locally.

The product does not need separate user experiences on day one.  A single
"Remote site" page can expose two clearly separated sections—**Agent trust &
lifecycle** and **Device inventory & access policy**—backed by distinct data
models, permissions and audit events.
