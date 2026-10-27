# Security policy

Pre-1.0, unaudited developer software. No security certification, OAuth compatibility or absolute protection is claimed.

## Threat model

- Prompt forgery: requests and handoffs are transport only. Approval requires the consuming application's allowlisted human session. Never expose an approval operation to an agent, enrollment endpoint or service API key.
- Key substitution: compute SHA-256 of SPKI DER from the stored Ed25519 key on the server. Owner and tester independently compare it to the original request. Reject mismatches before using the config.
- Shared grants: persist a distinct grant for each key and bind it to one synthetic account. Read current approval, enabled state, expiry and scopes on every protected request.
- Distributed replay/revocation: consume nonces atomically and store hashed sessions in one shared durable database. Independent worker memory stores do not meet this requirement. Store adapters must enforce capacity and expiry transactionally.
- Client bypass/cross-account access: authorize every route server-side and query data using only the returned account ID. Reject caller-supplied account IDs, guessed record IDs, forbidden operations and extra fields. Local task allowlists are not a security boundary.
- Self-approval: owner authentication and its allowlist belong to the application. Approval records must be immutable to enrollment and agent callers. Keep `approvedBy` and `approvedAt` with the grant, not in an agent-controlled config.
- Artifacts: never print keys, cookies, proofs, private account content or upstream error bodies. Audit fields are only `agentId`, `grantId`, `action`, `timestamp`, `outcome`. Do not enable authenticated traces or request-body logging.
- Legacy access: saved-browser-state and Clerk enrollment modes are removed. Never reuse a human or owner account for agent testing.
- Long-lived access: applications must default grants to at most seven days and enforce expiry server-side. Sessions default to five minutes. Ending a session deletes durable authority; disabling a grant affects live sessions on their next check.

The SDK denies sessions lacking recorded approval, verifies Ed25519 proofs with a fresh nonce and exact origin, and hashes random server session tokens. HTTPS cookies are host-only, Secure, HttpOnly and SameSite=Strict. Origin checks do not replace an application's authorization, CSRF handling or ingress controls.

## Deployment boundary

Run the trusted adapter under an OS account inaccessible to the agent's shell and filesystem. Permissions such as 0600 do not protect a key from another process under the same user. Windows requires equivalent ACLs. A compromised application origin or trusted host can defeat the boundary.

Paid model calls are application policy, not a browser capability. Keep them OFF unless the consuming application enforces an owner-approved hard budget with atomic reservation and reconciliation. An amount in a config is not enforcement. Do not expose billing, administration, credentials or another account through the test principal.

Revocation applies to future authorization checks, not completed writes or already-running jobs. Session cleanup can fail; close local resources, report the failure and rely on the application-side expiry and disable controls. Network failures must never be reported as success.

## Reporting

Use GitHub private vulnerability reporting when enabled. Otherwise use GitHub Issues only to request a private reporting channel, without publishing actionable exploits, credentials or personal details. No security email address or response SLA is claimed.
