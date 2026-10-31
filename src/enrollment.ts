/** Enrollment never authorizes access. The application owns the scope registry and approval. */
import { createHash, createPublicKey, randomUUID } from "node:crypto";
import { z } from "zod";

const scope = z.string().regex(/^[a-z][a-z0-9_-]{0,31}:[a-z][a-z0-9_-]{0,31}$/);
const requestSchema = z.object({
  client: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
  project: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
  publicKey: z.string().max(1024),
  scopes: z.array(scope).min(1).max(32),
}).strict();
/** Backward compatible sample scopes. A consuming app must supply its actual registry. */
const DEFAULT_SCOPES = ["workspace:read", "test-records:write"] as const;
export function fingerprintPublicKey(pem: string) {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== "ed25519") throw Error("ED25519_REQUIRED");
  return createHash("sha256").update(key.export({ format: "der", type: "spki" })).digest("base64");
}
export function prepareEnrollment(input: unknown, options: { allowedScopes?: readonly string[] } = {}) {
  const request = requestSchema.parse(input);
  const allowed = options.allowedScopes ?? DEFAULT_SCOPES;
  if (!allowed.length || allowed.length > 128 || allowed.some(s => !scope.safeParse(s).success))
    throw Error("SCOPE_REGISTRY_INVALID");
  if (request.scopes.some(s => !allowed.includes(s))) throw Error("SCOPE_NOT_REGISTERED");
  const publicKey = createPublicKey(request.publicKey).export({ format: "pem", type: "spki" }).toString();
  const fingerprint = fingerprintPublicKey(publicKey);
  const id = randomUUID(), createdAt = Date.now();
  return {
    id, agentId: request.client, project: request.project, publicKey, fingerprint,
    userId: "user_agenttest" + randomUUID().replaceAll("-", ""),
    scopes: [...new Set(request.scopes)].sort(), paidModelCapMicrousd: 0,
    status: "pending" as const, enabled: false,
    createdAt, expiresAt: createdAt + 60 * 60 * 1000,
  };
}
