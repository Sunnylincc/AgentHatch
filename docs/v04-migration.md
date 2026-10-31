# Migrating to AgentHatch v0.4 (release candidate)

AgentHatch remains an application-side SDK and trusted local MCP/CLI runtime. It is **not** a hosted identity provider or a universal third-party website login.

## Changes
- The application can supply its own approved scope registry with `prepareEnrollment(input, { allowedScopes })`; the built-in demo registry remains restricted to `workspace:read` and `test-records:write`.
- The signed-login protocol, human-only approval requirement, and fixed three authentication routes remain the same.
- `RedisDelegationStore` supports shared atomic nonce replay protection and revocable sessions. Supply a suitably configured, reliable Redis client with `set(key,value,{NX,PX})`, `get` and `del`; enable TLS/authentication and bounded memory operationally. Do not use the in-memory store for distributed deployments.
- `agenthatch init ./config.local.json` creates an owner-only starter template; it does not generate credentials or approve agents.
- `agenthatch doctor ./config.local.json local-tests sample https://app.example.com [--network]` verifies a trusted local key match and, optionally, that anonymous identity access is denied.
- `agenthatch status ./config.local.json local-tests` lists configured projects and allowed tasks, not live remote sessions.
- Owner-authored task steps may use `hidden` and `assert-text`; arbitrary code evaluation remains forbidden.
- Trusted Chromium runtime supports HTTP(S) proxy environment variables. Keep those variables out of the untrusted agent runtime.

## Production integration checklist
1. Isolate signing and browser execution from the agent's filesystem and OS account.
2. Use a distinct application account for each agent and filter every data query by the authorized user ID.
3. Maintain a human-authenticated owner-only approval surface and reload current grants on every protected route.
4. Use a durable shared atomic Redis store, TLS, ingress limits and strong tenant separation.
5. Revalidate authority or cancel long-running jobs, including after revocation.
6. Exercise signed login, scope reduction, cross-account denial, expiry and revocation end-to-end.

See `examples/delegated-app.mjs` for an intentionally synthetic HTTP fixture and `tests/probe-v04.test.ts` for a real HTTP probe across successive agent sessions. The example uses in-memory records and is **not** a production application or a Next.js deployment.

## Compatibility
The `agentdoor` executable alias and SDK exports remain. The old saved-browser-state/Clerk enrollment mode was removed in v0.3 and must not be restored. No personal credentials or customer account data should be committed.
