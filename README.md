# AgentHatch

Controlled test access for AI-assisted application development.

A free, MIT-licensed developer library with a local CLI and stdio MCP interface. Application owners control agent identities and access policies. No hosted AgentDoor account or subscription is required.

## Status: 0.2

Two adapters are available:

- **Delegated access:** an application-side SDK accepts an owner-approved agent identity, establishes a dedicated agent session, enforces application permissions, and revokes server-side sessions.
- **Legacy Clerk enrollment:** a human signs in once and the tool reuses stored browser state. This adapter does not remotely revoke Clerk sessions or implement application permissions.

Delegated access requires the target application to integrate the SDK. Installing this repository alone cannot grant access to an arbitrary website or create a Clerk account. An AgentDoor principal is a separate application identity; it is not automatically a Clerk user. Keep personal/admin accounts separate.

The signed-login protocol is project-specific, not OAuth or an externally audited standard. Do not treat it as a replacement for a mature identity provider across unrelated third-party services.

## Install

Node.js 24 is required.

```sh
git clone https://github.com/Sunnylincc/AgentHatch.git
cd AgentHatch
npm ci
npm run build
npx playwright install chromium
```

No model API key is needed. Applications and external providers may have their own charges. Paid model operations are not enabled by this tool.

## Delegated access: one-time setup

1. Generate a local agent identity:

```sh
node dist/main.js identity:init /absolute/private/agentdoor-identity
```

The private key remains in `identity.local.pem` with mode 0600. Only give the application owner the contents of `identity.public.pem`. Never give the model a private key, session cookie, or administrator API key. On Windows, restrict directory/file ACLs to the trusted account; POSIX modes are insufficient.

2. The application owner installs the SDK and registers a grant binding that public key to a dedicated agent ID, application user ID, explicit scopes and expiry. See [application integration](docs/application-integration.md). This is the human authorization step. The agent cannot register or expand its own grant through MCP.

3. Create an owner-protected configuration from `examples/delegated-config.json`. Replace the origin, identity path and grant/account identifiers. Run:

```sh
chmod 600 config.local.json
node dist/main.js list_projects ./config.local.json local-tests
node dist/main.js shell ./config.local.json local-tests
```

Send one JSON object per line:

```json
{"command":"start_test_session","input":{"project":"sample"}}
{"command":"run_task","input":{"handle":"RETURNED_HANDLE","task":"dashboard-visible"}}
{"command":"session_status","input":{"handle":"RETURNED_HANDLE"}}
{"command":"end_test_session","input":{"handle":"RETURNED_HANDLE"}}
```

Only opaque handles and sanitized results are returned. The trusted browser adapter signs a fresh request and receives an HttpOnly cookie directly. No password, OTP, personal browser state or authentication link is passed through the model. Local cryptographic credentials still exist; this is not credential-free authentication.

## Owner control and revocation

The SDK calls the application's `getGrant` callback on **every protected request**, not just login. The owner can change scopes, disable a grant or shorten its expiry. Existing sessions immediately follow the updated policy when they make their next request. Changing the bound account, agent ID or public key invalidates existing sessions.

Every protected application/API route must call `authorize(request, requiredScope)` and use the returned account ID for data access. UI task allowlists alone do not enforce permissions. Permissions do not affect already-running work or unrelated application sessions; long-running operations need application-side cancellation and budget enforcement.

For delegated access, ending a handle calls the application's revoke endpoint before browser cleanup. A successful response reports `remoteRevocation: "confirmed"`. Failure is reported as `cleanup_failed`, not success. Ending an enrollment-based Clerk handle still reports `not_verified` for remote revocation.

## MCP

```json
{
  "mcpServers": {
    "agentdoor": {
      "command": "node",
      "args": [
        "/absolute/path/AgentHatch/dist/main.js",
        "mcp",
        "/absolute/path/config.local.json",
        "local-tests"
      ]
    }
  }
}
```

Tools: `list_projects`, `start_test_session`, `session_status`, `run_task`, `end_test_session`.

Local stdio only. Client labels are trusted-launcher policy labels, not credentials. The OS must restrict config, identity and process access. An agent with arbitrary shell access as the owner can read owner files and is outside this boundary. Remote ChatGPT/Claude cloud connectors are not implemented or claimed.

## Legacy Clerk enrollment

Use `examples/config.json`, select a dedicated Clerk test account and explicitly allowlist its application and Clerk resource origins. Then run:

```sh
node dist/main.js enroll ./config.local.json local-tests sample
```

A human must sign in in the opened browser. Browser state is saved under `~/.agentdoor/` and is sensitive. This mode requires no application SDK integration but does not supply delegated application permissions or remote session revocation. It does not satisfy passwordless agent onboarding.

## Verification and limits

```sh
npm test
npm run typecheck
npm run build
npm run test:browser
```

The default suite covers cryptographic verification, replay rejection, scope changes, account binding, expiration, server-side revocation, real HTTP integration, local policy handling and the actual SDK MCP handshake. Existing browser fixtures are mocked; the HTTP authorization tests use real requests and signatures.

`test:browser` launches real Chromium against `examples/delegated-app.mjs`. It tests automatic agent login, scoped writes, a fresh session, owner policy changes and remote revocation. It requires a successful Playwright Chromium installation. It is separate from the default suite and must not be reported as passing when browser installation or launch fails.

The local example uses in-memory data and a single-process session/replay store. Production applications must supply shared, durable, atomic storage, TLS, ingress rate limits and tenant isolation. No external application has yet been verified with the delegated adapter. This release has not received an independent security audit.

See [SECURITY.md](SECURITY.md) for the trust boundary and disclosure guidance.
