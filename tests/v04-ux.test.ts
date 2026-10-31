import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createConfigTemplate } from "../src/cli.js";
import { publicError } from "../src/error.js";
import { chromiumProxy } from "../src/proxy.js";
import { schema } from "../src/config.js";
test("init creates safe example and refuses overwrite", async () => {
  const dir = await mkdtemp(join(tmpdir(), "agenthatch-init-")), path = join(dir, "config.json");
  try {
    await createConfigTemplate(path);
    assert.ok((await readFile(path, "utf8")).includes("REPLACE_APPROVED_GRANT"));
    await assert.rejects(createConfigTemplate(path));
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test("public errors omit private upstream messages", () => {
  assert.equal(publicError(Error("TASK_DENIED")), "TASK_DENIED");
  assert.equal(publicError(Error("private upstream token")), "REQUEST_FAILED");
});
test("authenticated proxy settings are parsed but not reflected", () => {
  const p = chromiumProxy({ HTTPS_PROXY: "http://proxy-user:proxy-password@127.0.0.1:8080", NO_PROXY: "localhost" });
  assert.equal(p?.server, "http://127.0.0.1:8080");
  assert.equal(p?.username, "proxy-user"); assert.equal(p?.bypass, "localhost");
  assert.throws(() => chromiumProxy({ HTTPS_PROXY: "file:///etc/passwd" }));
  assert.equal(chromiumProxy({}), undefined);
});
test("assert-text and hidden steps are permitted; arbitrary evaluate is not", () => {
  const sample = { auth: { mode: "delegated", grantId: "g", identityFile: "/private/id" },
    origin: "https://app.example.com", resourceOrigins: [], loginPath: "/agentdoor/session", dashboardPath: "/dashboard",
    accountId: "user_test", sessionSeconds: 30, clients: ["local"],
    tasks: { check: { steps: [{ kind: "assert-text", selector: "h1", value: "Welcome" }, { kind: "hidden", selector: "#loading" }] } } };
  assert.ok(schema.parse({ projects: { sample } }));
  assert.throws(() => schema.parse({ projects: { sample: { ...sample, tasks: { check: { steps: [{ kind: "evaluate", selector: "h1" }] } } } } }));
});
