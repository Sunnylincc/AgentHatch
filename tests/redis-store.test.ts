import { test } from "node:test";
import assert from "node:assert/strict";
import { RedisDelegationStore, type RedisCommandClient } from "../src/redis-store.js";

function fakeRedis() {
  const records = new Map<string, { value: string; expiry: number }>();
  const redis: RedisCommandClient = {
    async set(k, value, options) {
      const current = records.get(k);
      if (options.NX && current && current.expiry > Date.now()) return null;
      records.set(k, { value, expiry: Date.now() + options.PX });
      return "OK";
    },
    async get(k) {
      const value = records.get(k);
      return value && value.expiry > Date.now() ? value.value : null;
    },
    async del(k) { return records.delete(k) ? 1 : 0; },
  };
  return redis;
}
test("shared Redis store rejects nonce replay between independent instances", async () => {
  const r = fakeRedis(), a = new RedisDelegationStore(r), b = new RedisDelegationStore(r);
  const expires = Date.now() + 60000;
  const results = await Promise.all([a.consumeNonce("same", expires), b.consumeNonce("same", expires)]);
  assert.deepEqual(results.sort(), [false, true]);
});
test("sessions persist between instances and a revoked session stays revoked", async () => {
  const r = fakeRedis(), a = new RedisDelegationStore(r), b = new RedisDelegationStore(r);
  const s = { hash: "a".repeat(64), grantId: "g", binding: "b", expiresAt: Date.now() + 300000 };
  await a.put(s);
  assert.deepEqual(await b.get(s.hash), s);
  await b.delete(s.hash);
  assert.equal(await a.get(s.hash), null);
});
test("expired nonce/session is never accepted", async () => {
  const r = fakeRedis(), a = new RedisDelegationStore(r);
  assert.equal(await a.consumeNonce("bad", Date.now() - 1), false);
  await assert.rejects(a.put({ hash: "b".repeat(64), grantId: "g", binding: "b", expiresAt: Date.now() - 1 }));
});
