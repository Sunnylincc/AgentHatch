import { z } from "zod";
import { isAbsolute } from "node:path";
import { readFile, lstat } from "node:fs/promises";
const alias = z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/);
const origin = z
  .string()
  .url()
  .refine((s) => {
    const u = new URL(s);
    return (
      u.origin === s &&
      (u.protocol === "https:" ||
        (u.protocol === "http:" &&
          ["localhost", "127.0.0.1"].includes(u.hostname)))
    );
  });
const step = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("visible"),
      selector: z.string().min(1).max(500),
    })
    .strict(),
  z
    .object({ kind: z.literal("click"), selector: z.string().min(1).max(500) })
    .strict(),
  z
    .object({
      kind: z.literal("fill"),
      selector: z.string().min(1).max(500),
      value: z.string().max(1000),
    })
    .strict(),
]);
export const schema = z
  .object({
    projects: z.record(
      alias,
      z
        .object({
          auth: z
            .object({
              mode: z.literal("delegated"),
              grantId: z.string().min(1).max(128),
              identityFile: z.string().min(1).max(4096).refine(isAbsolute),
            })
            .strict()
            .optional(),
          origin,
          resourceOrigins: z.array(origin).max(10),
          loginPath: z.string().regex(/^\/(?!\/)[^?#]*$/),
          dashboardPath: z.string().regex(/^\/(?!\/)[^?#]*$/),
          accountId: z.string().regex(/^user_[a-zA-Z0-9]+$/),
          sessionSeconds: z.number().int().min(10).max(1800),
          clients: z.array(alias).min(1).max(20),
          tasks: z.record(
            alias,
            z.object({ steps: z.array(step).min(1).max(20) }).strict(),
          ),
        })
        .strict(),
    ),
  })
  .strict();
export type Config = z.infer<typeof schema>;
export async function loadConfig(path: string): Promise<Config> {
  const stat = await lstat(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    (process.platform !== "win32" && stat.mode & 0o077)
  )
    throw new Error("CONFIG_PERMISSIONS");
  if (stat.size > 65536) throw new Error("CONFIG_TOO_LARGE");
  return schema.parse(JSON.parse(await readFile(path, "utf8")));
}
export function destination(origin: string, path: string) {
  const u = new URL(path, origin);
  if (u.origin !== origin || u.username || u.password || u.hash || u.search)
    throw new Error("DESTINATION_DENIED");
  return u.href;
}
