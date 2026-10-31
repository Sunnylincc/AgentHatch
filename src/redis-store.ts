/** Shared, atomic Redis-backed implementation for production deployments.
 * Supply a Redis client with SET NX PX, GET and DEL support, such as node-redis.
 * The caller owns authentication, TLS, availability and capacity limits.
 */
import { createHash } from "node:crypto";
import type { DelegationStore, StoredAgentSession } from "./delegation.js";
export interface RedisCommandClient {
  set(key: string, value: string, options: { PX: number; NX?: true }): Promise<string | null>;
  get(key: string): Promise<string | null>;
  del(key: string): Promise<number>;
}
export class RedisDelegationStore implements DelegationStore {
  constructor(private redis: RedisCommandClient, private prefix = "agenthatch:v1:") {
    if (!/^[a-zA-Z0-9:_-]{1,80}$/.test(prefix)) throw Error("REDIS_PREFIX_INVALID");
  }
  private key(kind: string, id: string) {
    return this.prefix + kind + ":" + createHash("sha256").update(id).digest("hex");
  }
  async consumeNonce(key: string, expiresAt: number): Promise<boolean> {
    const ttl = expiresAt - Date.now();
    if (!Number.isSafeInteger(ttl) || ttl <= 0 || ttl > 120000) return false;
    return (await this.redis.set(this.key("nonce", key), "1", { NX: true, PX: ttl })) === "OK";
  }
  async put(session: StoredAgentSession): Promise<void> {
    const ttl = session.expiresAt - Date.now();
    if (!/^[a-f0-9]{64}$/.test(session.hash) || !session.grantId || !session.binding ||
      !Number.isSafeInteger(ttl) || ttl <= 0 || ttl > 1800000) throw Error("SESSION_STORAGE_DENIED");
    const result = await this.redis.set(this.key("session", session.hash), JSON.stringify(session), { PX: ttl });
    if (result !== "OK") throw Error("SESSION_STORAGE_FAILED");
  }
  async get(hash: string): Promise<StoredAgentSession | null> {
    if (!/^[a-f0-9]{64}$/.test(hash)) return null;
    const encoded = await this.redis.get(this.key("session", hash));
    if (!encoded) return null;
    try {
      const data: unknown = JSON.parse(encoded);
      if (typeof data !== "object" || data === null) return null;
      const s = data as Record<string, unknown>;
      if (s.hash !== hash || typeof s.grantId !== "string" ||
        typeof s.binding !== "string" || typeof s.expiresAt !== "number" ||
        s.expiresAt <= Date.now()) return null;
      return s as unknown as StoredAgentSession;
    } catch { return null; }
  }
  async delete(hash: string): Promise<void> {
    if (!/^[a-f0-9]{64}$/.test(hash)) return;
    await this.redis.del(this.key("session", hash));
  }
}
