export interface ProxySettings { server: string; username?: string; password?: string; bypass?: string }
/** Read proxy settings only from the trusted launcher, never agent input. */
export function chromiumProxy(env: NodeJS.ProcessEnv = process.env): ProxySettings | undefined {
  const raw = env.HTTPS_PROXY || env.https_proxy || env.HTTP_PROXY || env.http_proxy;
  if (!raw) return undefined;
  let u: URL;
  try { u = new URL(raw); } catch { throw Error("PROXY_CONFIG_INVALID"); }
  if (!["http:", "https:"].includes(u.protocol) || !u.hostname ||
      (u.pathname && u.pathname !== "/") || u.search || u.hash) throw Error("PROXY_CONFIG_INVALID");
  const bypass = (env.NO_PROXY || env.no_proxy || "").split(",").map(v => v.trim()).filter(Boolean).join(",");
  return { server: u.protocol + "//" + u.host,
    ...(u.username ? { username: decodeURIComponent(u.username) } : {}),
    ...(u.password ? { password: decodeURIComponent(u.password) } : {}),
    ...(bypass ? { bypass } : {}) };
}
