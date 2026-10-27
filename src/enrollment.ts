/** Enrollment preparation is not authorization. Persist this disabled result in the application. */
import { createHash, createPublicKey, randomUUID } from "node:crypto";
import { z } from "zod";
const requestSchema = z.object({
  client: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
  project: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
  publicKey: z.string().max(1024),
  scopes: z.array(z.enum(["workspace:read", "test-records:write"])).min(1).max(2),
}).strict();
export function fingerprintPublicKey(pem: string) {
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== "ed25519") throw Error("ED25519_REQUIRED");
  return createHash("sha256").update(key.export({format:"der",type:"spki"})).digest("base64");
}
export function prepareEnrollment(input: unknown) {
  const request = requestSchema.parse(input);
  const publicKey = createPublicKey(request.publicKey).export({format:"pem",type:"spki"}).toString();
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
