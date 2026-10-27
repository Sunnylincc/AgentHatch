# AgentHatch

Controlled test access for AI-assisted application development. Free, open-source developer software under the MIT license. Application owners retain control of identities, permissions and revocation.

## Status: 0.3

AgentHatch provides an application-side authorization SDK, local CLI and stdio MCP interface. It is not a hosted service, owner console, identity provider or cloud connector. Application-specific approval pages, databases and deployments belong in the consuming application's repository.

Delegated signed access only. Legacy browser-state enrollment has been removed. Existing SDK class and HTTP route names remain compatible; the `agentdoor` CLI alias is retained alongside `agenthatch`. No real application, owner or tester configuration belongs in this repository.

## Install

Node.js 24 is required.

```sh
git clone https://github.com/Sunnylincc/AgentHatch.git
cd AgentHatch
npm ci
npm run build
npx playwright install chromium
```

No model API key is required. Paid model operations are not enabled by this library.

## Owner-approved access

1. The tester generates its keypair in its own trusted runtime:

```sh
node dist/main.js identity:init /absolute/private/agent-identity
```

Only its public key goes to the application owner. The private key never belongs in chat, Git, CI, a prompt, an environment variable or an agent-readable filesystem. Use a separate trusted signing/browser process. See [runtime isolation](docs/runtime-isolation.md).

2. The application calls `prepareEnrollment({client, project, publicKey, scopes})` and persists the disabled result. A request, signed proof, local configuration or prompt grants no access. Supported enrollment scopes are `workspace:read` and `test-records:write`. The initial lifetime is one hour; applications must cap owner-selected lifetimes at seven days.

3. The application's human-authenticated owner surface recomputes the fingerprint from the stored public key and displays the exact account, scopes, expiry and paid-model policy. Only an explicitly allowlisted human owner may approve, reject or disable. Approval records `approvedBy` and `approvedAt` in the durable grant. Keep audit events separate and minimal. The SDK refuses login when these approval fields are absent, even if `enabled` was toggled.

4. After approval, the application supplies a public handoff summary. The tester compares client, fingerprint, scopes and isolated account with the original request and the owner's approval summary. Any mismatch stops the test. A substituted key and its matching fingerprint are not sufficient if the original request is not independently checked by the tester and owner.

5. The trusted local adapter creates short-lived sessions using fresh Ed25519 proofs. Every protected application request reloads the grant and checks account binding, scopes, approval, expiry and enabled state. Applications must supply one shared durable atomic nonce/session store; the memory example is for local development only.

The application must enforce the account boundary even for direct HTTP calls. Task lists are conveniences. They do not prevent access to an unprotected application route. Never map an agent principal into a human or administrator account.

## Local configuration and checks

Use `examples/delegated-config.json`. Replace only the public handoff metadata and the absolute local identity path. Confirm the `expected` fingerprint matches the key generated in this runtime and scopes match the original request. Never replace the key to make a mismatched handoff pass.

```sh
chmod 600 config.local.json
node dist/main.js verify-config ./config.local.json local-tests sample https://app.example.com
node dist/main.js list_projects ./config.local.json local-tests
node dist/main.js probe ./config.local.json local-tests sample https://app.example.com
node dist/main.js shell ./config.local.json local-tests
```

`verify-config` checks the local key and the independently supplied expected origin; it does not approve anything. The probe requires the application's isolated `/agentdoor/records` API. It tests scoped writes, cross-account denial, a fresh session, remote revocation and rejection of the old cookie. It returns booleans only; cookies and signed proofs stay inside the trusted process.

Send one JSON object per line to the same persistent shell process:

```json
{"command":"start_test_session","input":{"project":"sample"}}
{"command":"run_task","input":{"handle":"RETURNED_HANDLE","task":"workspace-visible"}}
{"command":"run_task","input":{"handle":"RETURNED_HANDLE","task":"save-test-record"}}
{"command":"end_test_session","input":{"handle":"RETURNED_HANDLE"}}
```

Successful delegated cleanup reports `remoteRevocation: "confirmed"`. Failed remote cleanup closes local browser resources but returns `cleanup_failed`; it must not be reported as revocation success.

## MCP

Use the trusted launcher under a separate OS account. Give the untrusted agent only this interface, not that account's shell or key directory.

```json
{"mcpServers":{"agenthatch":{"command":"node","args":["/absolute/path/AgentHatch/dist/main.js","mcp","/absolute/private/config.local.json","local-tests"]}}}
```

Tools: `list_projects`, `start_test_session`, `session_status`, `run_task`, `end_test_session`. Local stdio only; no remote cloud connector is claimed.

## Verification

```sh
npm run privacy:check
npm run typecheck
npm test
npm run test:browser
```

Browser tests launch actual Chromium against a local synthetic application. No production credentials are required. Each SDK instance limits session creation to 60 attempts per minute; applications must supply shared `admitSession` and ingress limits for distributed deployments.

This pre-1.0 project is unaudited. The signed protocol is project-specific, not OAuth. It cannot isolate an agent that shares the signing account's OS privileges, guarantee an application's route coverage, impose a model budget by itself, or cancel already-running external work. See [SECURITY.md](SECURITY.md), [application integration](docs/application-integration.md) and [contribution rules](CONTRIBUTING.md).
