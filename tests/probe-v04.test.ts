import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { initializeIdentity, identityFingerprint } from "../src/identity.js";
import { probe } from "../src/probe.js";
import type { Config } from "../src/config.js";
test("real HTTP fixture: isolated records, new session persistence and revocation probe", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agenthatch-probe-"));
  let child: ReturnType<typeof spawn> | undefined;
  try {
    const keys = await initializeIdentity(join(dir, "identity"));
    const grant = { id: "probe-grant", agentId: "probe-agent", userId: "user_probe",
      publicKey: await readFile(keys.publicFile, "utf8"),
      scopes: ["workspace:read", "test-records:write"], enabled: true,
      approvedBy: "user_owner", approvedAt: Date.now(), expiresAt: Date.now() + 120000 };
    const grants = join(dir, "grants.json");
    await writeFile(grants, JSON.stringify([grant]), { mode: 0o600 });
    child = spawn(process.execPath, ["examples/delegated-app.mjs"], {
      env: { ...process.env, AGENTDOOR_GRANTS_FILE: grants }, stdio: ["ignore", "pipe", "pipe"] });
    const lines = createInterface({ input: child.stdout! });
    const origin = await new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(() => reject(Error("SERVER_TIMEOUT")), 15000);
      child!.once("exit", () => { clearTimeout(timeout); reject(Error("SERVER_EXIT")); });
      lines.once("line", line => { clearTimeout(timeout); resolve(JSON.parse(line).origin); });
    });
    const p: Config["projects"][string] = {
      auth: { mode: "delegated", grantId: grant.id, identityFile: keys.privateFile },
      expected: { fingerprint: await identityFingerprint(keys.privateFile), agentId: grant.agentId, scopes: grant.scopes },
      origin, resourceOrigins: [], loginPath: "/agentdoor/session", dashboardPath: "/agentdoor/workspace",
      accountId: grant.userId, sessionSeconds: 30, clients: ["local"],
      tasks: { check: { steps: [{ kind: "visible", selector: "main h1" }] } }
    };
    assert.deepEqual(await probe(p), {
      authenticated: true, isolatedWrite: true, crossAccountDenied: true,
      freshSessionPersistence: true, remoteRevocation: true, oldSessionRejected: true
    });
  } finally {
    child?.kill("SIGTERM");
    await rm(dir, { recursive: true, force: true });
  }
});
