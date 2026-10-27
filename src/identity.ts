import {
  generateKeyPairSync,
  sign,
  randomUUID,
  createPrivateKey,
} from "node:crypto";
import { mkdir, writeFile, lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
export async function initializeIdentity(directory: string) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await lstat(directory);
  if (
    stat.isSymbolicLink() ||
    !stat.isDirectory() ||
    (process.platform !== "win32" && stat.mode & 0o077)
  )
    throw Error("IDENTITY_DIRECTORY_DENIED");
  const keys = generateKeyPairSync("ed25519");
  const privateFile = join(directory, "identity.local.pem"),
    publicFile = join(directory, "identity.public.pem");
  await writeFile(
    privateFile,
    keys.privateKey.export({ type: "pkcs8", format: "pem" }),
    { flag: "wx", mode: 0o600 },
  );
  await writeFile(
    publicFile,
    keys.publicKey.export({ type: "spki", format: "pem" }),
    { flag: "wx", mode: 0o644 },
  );
  return { privateFile, publicFile };
}
export async function signSessionRequest(
  file: string,
  origin: string,
  grantId: string,
) {
  const stat = await lstat(file);
  if (
    stat.isSymbolicLink() ||
    !stat.isFile() ||
    stat.size > 4096 ||
    (process.platform !== "win32" && stat.mode & 0o077)
  )
    throw Error("IDENTITY_FILE_DENIED");
  const key = createPrivateKey(await readFile(file));
  if (key.asymmetricKeyType !== "ed25519") throw Error("IDENTITY_KEY_DENIED");
  const payload = Buffer.from(
    JSON.stringify({
      v: 1,
      audience: origin,
      grantId,
      nonce: randomUUID(),
      issuedAt: Date.now(),
    }),
  ).toString("base64url");
  return {
    payload,
    signature: sign(null, Buffer.from(payload), key).toString("base64url"),
  };
}
