# Runtime isolation

Keep the browser/signing process under a trusted operating-system account or in an isolated container. An untrusted agent must only receive the fixed MCP tools; it must not share that account's shell, filesystem, process environment, container socket or debugging port.

Owner setup:

1. Run the MCP server and its browser under a separate trusted account. Keep identity and configuration files outside the source checkout, with directories mode 0700 and files mode 0600. On Windows, apply equivalent account ACLs.
2. Do not mount that account's identity directory into the agent runtime. Do not place keys in agent prompts, environment variables, workflow secrets or repository files. Give the agent access only to the configured tool interface through the trusted launcher.
3. Bind each public key to its own test principal and minimum server scopes. Keep unrelated human data, administration, money and paid model endpoints inaccessible to that principal.
4. Disable browser traces, debug logs, screenshots of authenticated content and request-body logging. Operational audit events should contain only a generic event name, result and timestamp; never cookies, signatures or record contents.
5. Use short server session lifetimes and revoke grants server-side when access ends. Failed remote cleanup must be reported, even though the local browser is closed. Do not assume closing a browser revokes server authority.

File permissions do not isolate two processes running as the same OS user. This repository cannot establish the deployment's OS boundary on its own, and does not claim to protect keys from an agent with owner-level shell access. A signed client configuration would not change that limitation.

The session protocol and existing CLI names are retained for compatibility. An owner console, hosted issuer, cloud connector and automatic OS sandbox provisioning are not included.
