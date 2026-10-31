import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { prepareEnrollment } from "../src/enrollment.js";
import { schema } from "../src/config.js";
const publicKey = generateKeyPairSync("ed25519").publicKey.export({ format: "pem", type: "spki" }).toString();
test("custom app scopes require an application-owned registry", () => {
  const input = { client: "qa", project: "sample", publicKey, scopes: ["documents:read"] };
  assert.throws(() => prepareEnrollment(input));
  const pending = prepareEnrollment(input, { allowedScopes: ["documents:read", "documents:write"] });
  assert.equal(pending.enabled, false);
  assert.deepEqual(pending.scopes, ["documents:read"]);
  assert.throws(() => prepareEnrollment({ ...input, scopes: ["documents:delete"] }, { allowedScopes: ["documents:read"] }));
  assert.throws(() => prepareEnrollment({ ...input, scopes: ["admin"] }, { allowedScopes: ["admin"] }));
});
test("handoff scope metadata accepts registered application scope names", () => {
  const p = { auth: { mode: "delegated", grantId: "g", identityFile: "/private/key" },
    expected: { fingerprint: "A".repeat(43) + "=", agentId: "qa", scopes: ["documents:read"] },
    origin: "https://app.example.com", resourceOrigins: [], loginPath: "/agentdoor/session",
    dashboardPath: "/dashboard", accountId: "user_test", sessionSeconds: 30, clients: ["qa"],
    tasks: { check: { steps: [{ kind: "visible", selector: "h1" }] } } };
  assert.ok(schema.parse({ projects: { example: p } }));
});
