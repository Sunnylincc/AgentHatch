# Security policy

AgentDoor is pre-1.0 developer software. It has not received an independent security audit. No security or compliance certification is claimed.

## Trust boundary

The application owner controls registered public keys, application user mappings, scopes and expiry. The local launcher and OS protect private identity files and config. A client label is not authentication. Agents with arbitrary shell access under the owner's OS account are outside this boundary.

Delegated access requires explicit target-application integration. Every protected page/API must enforce the application-side SDK's authorization and account isolation. This repository cannot grant permission on unrelated websites.

## Credentials

No personal passwords, OTPs or administrator API keys are required by the delegated adapter. Ed25519 private identity keys and browser session cookies are still credentials. Never commit, share, print, trace or screenshot them. Protect private files with owner-only access and Windows ACLs where applicable. Configuration must not contain embedded secret values or sensitive test data.

The legacy Clerk adapter saves sensitive browser state and does not remotely revoke Clerk sessions. Keep that mode separate from delegated access.

## Protections and residual risks

- Signed session requests are bound to an exact origin, registered grant, fresh timestamp and single-use nonce. The application controls account and scope selection.
- Sessions are random opaque cookies; server stores hashed tokens. HTTPS cookies are Secure, HttpOnly, SameSite=Strict and host-only.
- Grant state, scope, expiry and identity binding are checked on each protected request. Session revocation removes server-side authority, not just local browser state.
- Policy changes affect subsequent checks. They do not roll back completed operations or automatically cancel ongoing jobs.
- Browser task allowlists do not replace application authorization. Prompt-injected agents must still be denied by application-side checks. Rate limits and model budgets belong in the application.
- The signature exchange is project-specific. It is not a standards-complete OAuth, device-authorization or DPoP implementation.
- Memory storage is single-process development storage. Its nonce history is lost on restart. Distributed/production use requires a durable shared atomic store, consistency, ingress rate limits, TLS and resource limits. A cluster of independent memory stores permits replay and inconsistent revocation.
- Supporting resource origins are trusted dependencies. A compromised origin, application integration, OS account or signing key can undermine the boundary.
- Cleanup failure is an error. Killing the process can prevent cleanup; session expiry and owner-side grant revocation remain necessary.

## Reporting

Use GitHub private vulnerability reporting if the repository exposes that feature. Otherwise contact the maintainer through an established private channel to arrange disclosure. No monitored security email address is claimed. Do not publish working credentials, session artifacts or exploit details in a public issue.

Version 0.2 is the active development line. Older releases have no promised security backport policy.
