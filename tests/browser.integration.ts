import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { initializeIdentity } from "../src/identity.js";
import { DelegatedBrowser } from "../src/browser.js";
import { AgentDoor } from "../src/core.js";
import type { Config } from "../src/config.js";
import type { Grant } from "../src/delegation.js";
test("real Chromium: no human login, authenticated task, fresh session, scope edits and remote revocation", async () => {
  const root = await mkdtemp(join(tmpdir(), "agentdoor-"));
  const paths = await initializeIdentity(join(root, "identity"));
  const grant: Grant = {
    id: "browser-grant",
    userId: "user_browser",
    agentId: "browser-agent",
    publicKey: await readFile(paths.publicFile, "utf8"),
    scopes: ["notes:read", "notes:write"],
    enabled: true, approvedBy: "user_owner", approvedAt: Date.now(),
    expiresAt: Date.now() + 300000,
  };
  const file = join(root, "grants.local.json");
  const update = () =>
    writeFile(file, JSON.stringify([grant]), { mode: 0o600 });
  await update();
  const child = spawn(process.execPath, ["examples/delegated-app.mjs"], {
    env: { ...process.env, AGENTDOOR_GRANTS_FILE: file },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let door: AgentDoor | undefined;
  try {
    const lines = createInterface({ input: child.stdout });
    const origin = await new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(Error("SERVER_START_TIMEOUT")),
        15000,
      );
      child.once("exit", () => {
        clearTimeout(timeout);
        reject(Error("SERVER_START_FAILED"));
      });
      lines.once("line", (line) => {
        clearTimeout(timeout);
        resolve(JSON.parse(line).origin);
      });
    });
    const config: Config = {
      projects: {
        sample: {
          auth: {
            mode: "delegated",
            grantId: grant.id,
            identityFile: paths.privateFile,
          },
          origin,
          resourceOrigins: [],
          accountId: grant.userId,
          loginPath: "/unused",
          dashboardPath: "/dashboard",
          sessionSeconds: 30,
          clients: ["qa"],
          tasks: {
            read: {
              steps: [
                { kind: "visible", selector: "h1" },
                { kind: "visible", selector: "#identity" },
              ],
            },
            save: {
              steps: [
                {
                  kind: "fill",
                  selector: "textarea",
                  value: "Independent agent test",
                },
                { kind: "click", selector: "button" },
                {
                  kind: "visible",
                  selector:
                    '[data-note="true"]:has-text("Independent agent test")',
                },
              ],
            },
          },
        },
      },
    };
    door = new AgentDoor(config, "qa", new DelegatedBrowser(join(root, "states")));
    const first = await door.start("sample");
    assert.equal(first.state, "active");
    await door.run(first.handle, "read");
    await door.run(first.handle, "save");
    assert.equal((await door.end(first.handle)).remoteRevocation, "confirmed");
    await assert.rejects(door.run(first.handle, "read"));
    const second = await door.start("sample");
    await door.run(second.handle, "read");
    await door.run(second.handle, "save");
    grant.scopes = ["notes:read"];
    await update();
    await assert.rejects(door.run(second.handle, "save"));
    grant.enabled = false;
    await update();
    await assert.rejects(door.run(second.handle, "read"));
    await assert.rejects(door.start("sample"));
  } finally {
    await door?.close();
    child.kill("SIGTERM");
    await new Promise<void>((r) => {
      if (child.exitCode !== null) r();
      else child.once("exit", () => r());
    });
    await rm(root, { recursive: true, force: true });
  }
});
