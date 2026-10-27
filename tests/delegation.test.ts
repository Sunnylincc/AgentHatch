import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import {
  createDelegation,
  MemoryDelegationStore,
  type Grant,
} from "../src/delegation.js";
function setup() {
  const pair = generateKeyPairSync("ed25519");
  let grant: Grant = {
    id: "grant-test",
    agentId: "qa-agent",
    userId: "user_agent",
    publicKey: pair.publicKey
      .export({ type: "spki", format: "pem" })
      .toString(),
    scopes: ["portfolio:read"],
    enabled: true,
    expiresAt: Date.now() + 600000,
  };
  const origin = "https://app.example.com",
    store = new MemoryDelegationStore(),
    sdk = createDelegation({
      origin,
      getGrant: async (id) => (id === grant.id ? grant : null),
      store,
    });
  const body = (change: Record<string, unknown> = {}) => {
    const payload = Buffer.from(
      JSON.stringify({
        v: 1,
        audience: origin,
        grantId: grant.id,
        nonce: randomUUID(),
        issuedAt: Date.now(),
        ...change,
      }),
    ).toString("base64url");
    return {
      payload,
      signature: sign(null, Buffer.from(payload), pair.privateKey).toString(
        "base64url",
      ),
    };
  };
  const login = (value = body()) =>
    sdk.handle(
      new Request(origin + "/agentdoor/session", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(value),
      }),
    );
  const req = (path = "/dashboard", cookie = "") =>
    new Request(origin + path, { headers: { cookie } });
  return { sdk, origin, body, login, req, grant };
}
function cookie(r: Response) {
  return r.headers.get("set-cookie")!.split(";")[0];
}
test("real signed login yields isolated principal and application-enforced permissions", async () => {
  const t = setup(),
    r = await t.login();
  assert.equal(r.status, 201);
  const c = cookie(r);
  assert.match(r.headers.get("set-cookie")!, /HttpOnly/);
  assert.match(r.headers.get("set-cookie")!, /Secure/);
  assert.match(r.headers.get("set-cookie")!, /SameSite=Strict/);
  assert.deepEqual(await t.sdk.authorize(t.req("/data", c), "portfolio:read"), {
    agentId: "qa-agent",
    userId: "user_agent",
    grantId: "grant-test",
    scopes: ["portfolio:read"],
  });
  await assert.rejects(t.sdk.authorize(t.req("/data", c), "ledger:write"));
  assert.equal(
    (await t.sdk.handle(t.req("/agentdoor/identity", c))).status,
    200,
  );
  assert.equal(
    (
      await t.sdk.handle(
        t.req("/agentdoor/identity", "__Host-agentdoor=" + "f".repeat(64)),
      )
    ).status,
    403,
  );
});
test("owner policy changes apply to existing sessions and cannot change identity", async () => {
  const t = setup(),
    c = cookie(await t.login());
  t.grant.scopes = [];
  await assert.rejects(t.sdk.authorize(t.req("/data", c), "portfolio:read"));
  t.grant.scopes = ["ledger:write"];
  await t.sdk.authorize(t.req("/data", c), "ledger:write");
  t.grant.userId = "user_other";
  await assert.rejects(t.sdk.authorize(t.req("/data", c), "ledger:write"));
});
test("grant revocation invalidates existing sessions and prevents re-login", async () => {
  const t = setup(),
    c = cookie(await t.login());
  t.grant.enabled = false;
  await assert.rejects(t.sdk.authorize(t.req("/data", c), "portfolio:read"));
  assert.equal((await t.login()).status, 403);
});
test("remote session revocation invalidates a copied cookie; re-login is independent", async () => {
  const t = setup(),
    c = cookie(await t.login());
  assert.equal(
    (
      await t.sdk.handle(
        new Request(t.origin + "/agentdoor/revoke", {
          method: "POST",
          headers: { cookie: c },
        }),
      )
    ).status,
    200,
  );
  await assert.rejects(t.sdk.authorize(t.req("/data", c), "portfolio:read"));
  const next = cookie(await t.login());
  assert.notEqual(c, next);
  await t.sdk.authorize(t.req("/data", next), "portfolio:read");
});
test("reject replay, changed audience, expired proof, tampered signature and extra scopes", async () => {
  const t = setup(),
    p = t.body();
  assert.equal((await t.login(p)).status, 201);
  assert.equal((await t.login(p)).status, 403);
  for (const change of [
    { audience: "https://evil.example" },
    { issuedAt: Date.now() - 60000 },
    { grantId: "unknown" },
    { scopes: ["admin"] },
  ])
    assert.equal((await t.login(t.body(change))).status, 403);
  assert.equal(
    (await t.login({ ...t.body(), signature: "a".repeat(86) })).status,
    403,
  );
});
test("reject cross-origin requests, wrong methods, oversized input and expired grant", async () => {
  const t = setup();
  assert.equal(
    (
      await t.sdk.handle(
        new Request(t.origin + "/agentdoor/session", {
          method: "POST",
          headers: {
            origin: "https://evil.example",
            "content-type": "application/json",
          },
          body: JSON.stringify(t.body()),
        }),
      )
    ).status,
    403,
  );
  assert.equal(
    (await t.sdk.handle(new Request(t.origin + "/agentdoor/session"))).status,
    404,
  );
  assert.equal(
    (
      await t.sdk.handle(
        new Request(t.origin + "/agentdoor/session", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "x".repeat(5000),
        }),
      )
    ).status,
    403,
  );
  t.grant.expiresAt = Date.now() - 1;
  assert.equal((await t.login()).status, 403);
});
test("session expiration is checked at every application authorization", async () => {
  const t = setup(),
    c = cookie(await t.login());
  const original = Date.now;
  Date.now = () => original() + 400000;
  try {
    await assert.rejects(t.sdk.authorize(t.req("/data", c), "portfolio:read"));
  } finally {
    Date.now = original;
  }
});
test("HTTP application integration logs in, enforces scopes, rechecks owner policy and revokes", async () => {
  const pair = generateKeyPairSync("ed25519"),
    grant: Grant = {
      id: "http-grant",
      agentId: "agent",
      userId: "user_http",
      publicKey: pair.publicKey
        .export({ type: "spki", format: "pem" })
        .toString(),
      scopes: ["read"],
      enabled: true,
      expiresAt: Date.now() + 60000,
    };
  let sdk: ReturnType<typeof createDelegation>,
    origin = "";
  const server = createServer(async (req, res) => {
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(Buffer.from(chunk));
      const request = new Request(origin + req.url, {
        method: req.method,
        headers: req.headers as Record<string, string>,
        ...(chunks.length ? { body: Buffer.concat(chunks) } : {}),
      });
      let response: Response;
      if (req.url?.startsWith("/agentdoor/"))
        response = await sdk.handle(request);
      else {
        try {
          const principal = await sdk.authorize(
            request,
            req.method === "POST" ? "write" : "read",
          );
          response = Response.json({ userId: principal.userId });
        } catch {
          response = new Response("Forbidden", { status: 403 });
        }
      }
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(await response.text());
    } catch {
      res.writeHead(500);
      res.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const address = server.address();
  assert(address && typeof address !== "string");
  origin = `http://127.0.0.1:${address.port}`;
  sdk = createDelegation({
    origin,
    allowLocalHttp: true,
    getGrant: async (id) => (id === grant.id ? grant : null),
    store: new MemoryDelegationStore(),
  });
  try {
    const payload = Buffer.from(
      JSON.stringify({
        v: 1,
        audience: origin,
        grantId: grant.id,
        nonce: randomUUID(),
        issuedAt: Date.now(),
      }),
    ).toString("base64url");
    const r = await fetch(origin + "/agentdoor/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        payload,
        signature: sign(null, Buffer.from(payload), pair.privateKey).toString(
          "base64url",
        ),
      }),
    });
    assert.equal(r.status, 201);
    const c = cookie(r);
    assert.equal(
      (await fetch(origin + "/dashboard", { headers: { cookie: c } })).status,
      200,
    );
    assert.equal(
      (
        await fetch(origin + "/dashboard", {
          method: "POST",
          headers: { cookie: c },
        })
      ).status,
      403,
    );
    grant.scopes.push("write");
    assert.equal(
      (
        await fetch(origin + "/dashboard", {
          method: "POST",
          headers: { cookie: c },
        })
      ).status,
      200,
    );
    await fetch(origin + "/agentdoor/revoke", {
      method: "POST",
      headers: { cookie: c },
    });
    assert.equal(
      (await fetch(origin + "/dashboard", { headers: { cookie: c } })).status,
      403,
    );
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((e) => (e ? reject(e) : resolve())),
    );
  }
});
