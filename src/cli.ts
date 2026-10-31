import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { Config } from "./config.js";
import { identityFingerprint } from "./identity.js";
export async function createConfigTemplate(path: string) {
  const target = resolve(path);
  const sample = { projects: { sample: {
    auth: { mode: "delegated", grantId: "REPLACE_APPROVED_GRANT", identityFile: "/absolute/private/identity.local.pem" },
    expected: { fingerprint: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", agentId: "sample-agent", scopes: ["workspace:read"] },
    origin: "https://app.example.com", resourceOrigins: [], loginPath: "/agentdoor/session",
    dashboardPath: "/agentdoor/workspace", accountId: "user_agenttest",
    sessionSeconds: 300, clients: ["local-tests"],
    tasks: { "workspace-visible": { steps: [{ kind: "visible", selector: "main h1" }] } }
  } } };
  await writeFile(target, JSON.stringify(sample, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  return target;
}
export async function doctor(config: Config, client: string, project: string, origin: string, network = false) {
  const p = config.projects[project];
  if (!p || !p.clients.includes(client) || !p.expected || p.origin !== origin) throw Error("CONFIG_DENIED");
  if (await identityFingerprint(p.auth.identityFile) !== p.expected.fingerprint) throw Error("KEY_SUBSTITUTION_DENIED");
  const checks: { check: string; ok: boolean }[] = [{ check: "configuration", ok: true }, { check: "key_fingerprint", ok: true }];
  if (network) {
    let ok = false;
    try { const r = await fetch(origin + "/agentdoor/identity", { redirect: "manual", signal: AbortSignal.timeout(10000) });
      ok = r.status === 403;
    } catch { ok = false; }
    checks.push({ check: "unauthenticated_access_denied", ok });
  }
  return { ok: checks.every(c => c.ok), project, checks };
}
