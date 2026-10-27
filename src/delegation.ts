/** Application-side authorization. Mount only on applications you own. */
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { z } from "zod";
import { sessionAdmission } from "./rate-limit.js";
export interface Grant {
  id: string;
  agentId: string;
  userId: string;
  publicKey: string;
  scopes: string[];
  expiresAt: number;
  enabled: boolean;
}
export interface AgentPrincipal {
  agentId: string;
  userId: string;
  grantId: string;
  scopes: string[];
}
export interface StoredAgentSession {
  hash: string;
  grantId: string;
  binding: string;
  expiresAt: number;
}
/** Store methods must be shared and atomic across all server workers. */
export interface DelegationStore {
  consumeNonce(key: string, expiresAt: number): Promise<boolean>;
  put(session: StoredAgentSession): Promise<void>;
  get(hash: string): Promise<StoredAgentSession | null>;
  delete(hash: string): Promise<void>;
}
export class MemoryDelegationStore implements DelegationStore {
  private nonces = new Map<string, number>();
  private sessions = new Map<string, StoredAgentSession>();
  constructor(private limit = 10000) {}
  async consumeNonce(key: string, expiresAt: number) {
    const now = Date.now();
    for (const [k, v] of this.nonces) if (v <= now) this.nonces.delete(k);
    if (this.nonces.has(key) || this.nonces.size >= this.limit) return false;
    this.nonces.set(key, expiresAt);
    return true;
  }
  async put(s: StoredAgentSession) {
    for (const [k, v] of this.sessions)
      if (v.expiresAt <= Date.now()) this.sessions.delete(k);
    if (this.sessions.size >= this.limit) throw Error("CAPACITY");
    this.sessions.set(s.hash, s);
  }
  async get(hash: string) {
    return this.sessions.get(hash) ?? null;
  }
  async delete(hash: string) {
    this.sessions.delete(hash);
  }
}
const proof = z
  .object({
    payload: z
      .string()
      .regex(/^[A-Za-z0-9_-]+$/)
      .max(2000),
    signature: z
      .string()
      .regex(/^[A-Za-z0-9_-]+$/)
      .max(200),
  })
  .strict();
const claims = z
  .object({
    v: z.literal(1),
    audience: z.string(),
    grantId: z.string().min(1).max(128),
    nonce: z.string().uuid(),
    issuedAt: z.number().int(),
  })
  .strict();
const hash = (s: string) => createHash("sha256").update(s).digest("hex");
const binding = (g: Grant) =>
  hash(JSON.stringify([g.id, g.agentId, g.userId, g.publicKey]));
export class AgentAccessDenied extends Error {
  constructor() {
    super("AGENT_ACCESS_DENIED");
  }
}
export function createDelegation(options: {
  origin: string;
  getGrant: (id: string) => Promise<Grant | null>;
  store: DelegationStore;
  sessionSeconds?: number;
  allowLocalHttp?: boolean;
  /** Optional shared application-side admission check. Never trust client-supplied IP headers. */
  admitSession?: (request: Request) => Promise<boolean>;
}) {
  const origin = new URL(options.origin);
  if (
    origin.origin !== options.origin ||
    !(
      origin.protocol === "https:" ||
      (options.allowLocalHttp &&
        origin.protocol === "http:" &&
        ["127.0.0.1", "localhost"].includes(origin.hostname))
    )
  )
    throw Error("INVALID_APPLICATION_ORIGIN");
  const seconds = options.sessionSeconds ?? 300;
  const admitLocal = sessionAdmission();
  if (!Number.isInteger(seconds) || seconds < 10 || seconds > 1800)
    throw Error("INVALID_SESSION_LIFETIME");
  const secure = origin.protocol === "https:",
    cookie = secure ? "__Host-agentdoor" : "agentdoor_local";
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
  };
  const cookieValue = (value: string, maxAge: number) =>
    `${cookie}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
  const response = (status: number, value: object, setCookie?: string) =>
    new Response(JSON.stringify(value), {
      status,
      headers: {
        ...headers,
        ...(setCookie ? { "Set-Cookie": setCookie } : {}),
      },
    });
  function checkOrigin(request: Request) {
    if (new URL(request.url).origin !== options.origin)
      throw new AgentAccessDenied();
    const supplied = request.headers.get("origin");
    if (supplied && supplied !== options.origin) throw new AgentAccessDenied();
  }
  function token(request: Request) {
    const values = (request.headers.get("cookie") ?? "")
      .split(";")
      .map((x) => x.trim())
      .filter((x) => x.startsWith(cookie + "="));
    if (values.length !== 1) throw new AgentAccessDenied();
    const value = values[0].slice(cookie.length + 1);
    if (!/^[a-f0-9]{64}$/.test(value)) throw new AgentAccessDenied();
    return value;
  }
  async function current(request: Request) {
    checkOrigin(request);
    const h = hash(token(request)),
      s = await options.store.get(h);
    if (!s || s.expiresAt <= Date.now()) throw new AgentAccessDenied();
    const g = await options.getGrant(s.grantId);
    if (
      !g ||
      !g.enabled ||
      g.expiresAt <= Date.now() ||
      binding(g) !== s.binding
    )
      throw new AgentAccessDenied();
    return { s, g };
  }
  return {
    /** Call this inside EVERY protected application handler; scope comes from application code. */
    async authorize(
      request: Request,
      requiredScope: string,
    ): Promise<AgentPrincipal> {
      const { g } = await current(request);
      if (!g.scopes.includes(requiredScope)) throw new AgentAccessDenied();
      return {
        agentId: g.agentId,
        userId: g.userId,
        grantId: g.id,
        scopes: [...g.scopes],
      };
    },
    /** Fixed route paths: /agentdoor/session, /identity and /revoke. No redirects or CORS. */
    async handle(request: Request): Promise<Response> {
      try {
        checkOrigin(request);
        const path = new URL(request.url).pathname;
        if (path === "/agentdoor/session" && request.method === "POST") {
          if (!admitLocal() || (options.admitSession && !(await options.admitSession(request))))
            return response(429, { error: "SESSION_RATE_LIMITED" });
          if (
            !request.headers.get("content-type")?.startsWith("application/json")
          )
            return response(415, { error: "JSON_REQUIRED" });
          // Limit streaming input even when Content-Length is absent or dishonest.
          const reader = request.body?.getReader();
          if (!reader) throw new AgentAccessDenied();
          let bytes = 0,
            text = "";
          const decoder = new TextDecoder();
          try {
            while (true) {
              const part = await reader.read();
              if (part.done) break;
              bytes += part.value.length;
              if (bytes > 4096) {
                await reader.cancel();
                throw new AgentAccessDenied();
              }
              text += decoder.decode(part.value, { stream: true });
            }
            text += decoder.decode();
          } finally {
            reader.releaseLock();
          }
          const p = proof.parse(JSON.parse(text)),
            c = claims.parse(
              JSON.parse(Buffer.from(p.payload, "base64url").toString("utf8")),
            );
          if (
            c.audience !== options.origin ||
            Math.abs(Date.now() - c.issuedAt) > 30000
          )
            throw new AgentAccessDenied();
          const g = await options.getGrant(c.grantId);
          if (
            !g ||
            g.id !== c.grantId ||
            !g.enabled ||
            g.expiresAt <= Date.now()
          )
            throw new AgentAccessDenied();
          const key = createPublicKey(g.publicKey);
          if (
            key.asymmetricKeyType !== "ed25519" ||
            !verify(
              null,
              Buffer.from(p.payload),
              key,
              Buffer.from(p.signature, "base64url"),
            )
          )
            throw new AgentAccessDenied();
          if (
            !(await options.store.consumeNonce(
              `${g.id}:${c.nonce}`,
              Date.now() + 60000,
            ))
          )
            throw new AgentAccessDenied();
          const value = randomBytes(32).toString("hex"),
            expiresAt = Math.min(Date.now() + seconds * 1000, g.expiresAt);
          await options.store.put({
            hash: hash(value),
            grantId: g.id,
            binding: binding(g),
            expiresAt,
          });
          return response(
            201,
            { authenticated: true, expiresAt },
            cookieValue(
              value,
              Math.max(0, Math.floor((expiresAt - Date.now()) / 1000)),
            ),
          );
        }
        if (path === "/agentdoor/identity" && request.method === "GET") {
          const { g, s } = await current(request);
          return response(200, {
            agentId: g.agentId,
            userId: g.userId,
            grantId: g.id,
            expiresAt: s.expiresAt,
          });
        }
        if (path === "/agentdoor/revoke" && request.method === "POST") {
          // Idempotently delete even after the grant has been disabled.
          await options.store.delete(hash(token(request)));
          return response(200, { revoked: true }, cookieValue("", 0));
        }
        return response(404, { error: "NOT_FOUND" });
      } catch {
        return response(403, { error: "AGENT_ACCESS_DENIED" });
      }
    },
  };
}
