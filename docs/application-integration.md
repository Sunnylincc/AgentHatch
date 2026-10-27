# Application integration

This SDK is for applications whose owners explicitly choose to support agent accounts. It does not grant access to an unmodified third-party website.

## Register an identity

The owner receives only an agent's public key and creates an application-side grant:

```ts
import { createDelegation, MemoryDelegationStore, type Grant } from "agentdoor";

const grants: Grant[] = [
  {
    id: "qa-grant",
    agentId: "qa-agent",
    userId: "user_agenttest",
    publicKey: ownerApprovedPublicKeyPem,
    scopes: ["portfolio:read"],
    expiresAt: Date.now() + 60 * 60 * 1000,
    enabled: true,
  },
];

const agentAccess = createDelegation({
  origin: "https://app.example.com",
  getGrant: async (id) => grants.find((g) => g.id === id) ?? null,
  store: new MemoryDelegationStore(), // Single-process development ONLY.
  sessionSeconds: 300,
});
```

`userId` must identify a dedicated application agent account. It must never be selected from untrusted request input. Applications using Clerk must explicitly support this separate principal in their data authorization layer; the SDK does not impersonate or create Clerk users.

Load grants from an owner-controlled database or file. Make edits visible immediately and do not expose an unauthenticated grant-management endpoint. Authenticate and authorize human policy editors using the application's existing identity system.

## Mount the fixed endpoints

Pass a canonical Web `Request` to `agentAccess.handle()` at:

- `POST /agentdoor/session`
- `GET /agentdoor/identity`
- `POST /agentdoor/revoke`

Return the resulting `Response` with its headers, including `Set-Cookie`, unchanged. Do not log request bodies, cookies or signatures. Do not add permissive CORS or redirects. Configure a canonical origin; do not infer trust from arbitrary forwarded host headers.

The private SDK session cookie is Secure, HttpOnly, host-only and SameSite=Strict on HTTPS. Local HTTP is accepted only with an explicit `allowLocalHttp: true` setting and a loopback origin, for development.

## Enforce permissions on every application handler

```ts
async function readPortfolio(request: Request) {
  const agent = await agentAccess.authorize(request, "portfolio:read");
  return loadPortfolioOwnedBy(agent.userId);
}
```

Required scopes must be constants chosen by application code, not values supplied by the caller. Protect both HTML pages and APIs. Filter every database operation by the authorized principal's account. Distinguish human sessions from agent sessions explicitly and never silently elevate an agent to an administrator.

Reject missing or invalid agent authorization. Do not fall back to a different account after an error. Sensitive operations require explicit scopes and additional application checks. Enforce model budgets, payment restrictions and irreversible-operation approvals on the server, separately from browser task selectors.

Disabling a grant revokes its authority on subsequent checks. Changing scopes affects existing sessions. Changing a grant's account, agent ID or key invalidates the identity binding. Revoking a session deletes its server-side record; a copied cookie no longer authenticates. Ongoing jobs need their own cancellation/recheck mechanism.

## Storage contract

Implement `DelegationStore` with shared storage before using multiple workers or serverless instances:

- `consumeNonce(key, expiry)` must atomically insert only if the nonce has not been used. Its effect must be shared across workers.
- `put(session)` persists a session record indexed by its hashed token.
- `get(hash)` and `delete(hash)` must observe revocation consistently.
- Expire records and bound capacity.

`MemoryDelegationStore` is a bounded, single-process development implementation. Restarting it invalidates sessions but loses replay history; it is not suitable for distributed or production use. Place ingress rate and body-size limits before these endpoints as well.

## Local executable example

`examples/delegated-app.mjs` is a development fixture using the actual SDK. It reloads an owner-managed grants file on each authorization check and stores sample notes per account in process memory. It is not a SaaS application or a production storage adapter.

Run it with `AGENTDOOR_GRANTS_FILE=/absolute/path/grants.local.json node examples/delegated-app.mjs`. It prints a non-secret loopback origin. The grants file contains an array of `Grant` records. Use that exact origin and the corresponding identifiers in the private CLI configuration.

Run `npm run test:browser` for an automated real-browser example. The test creates temporary identities and grants and cleans them up. It performs no external provider login or model call.
