import { chromium, type BrowserContext, type Page } from "playwright";
import { mkdir, chmod, lstat } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "./config.js";
import { signSessionRequest } from "./identity.js";
import { destination } from "./config.js";
import { revokeAndClose } from "./cleanup.js";
import type { BrowserAdapter, BrowserSession, Step } from "./core.js";
export async function privateDirectory(path: string) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const s = await lstat(path);
  if (s.isSymbolicLink() || !s.isDirectory())
    throw new Error("STATE_DIRECTORY_DENIED");
  await chmod(path, 0o700);
}
export async function identity(page: Page): Promise<string | null> {
  return page.evaluate(() => {
    const c = (window as unknown as { Clerk?: { user?: { id: string } } })
      .Clerk;
    return c?.user?.id ?? null;
  });
}
function chromiumLaunchOptions() {
  const raw = process.env.HTTPS_PROXY || process.env.HTTP_PROXY ||
    process.env.https_proxy || process.env.http_proxy;
  if (!raw) return { headless: true };
  const url = new URL(raw);
  if (url.protocol !== "http:") throw new Error("UNSUPPORTED_PROXY_SCHEME");
  return {
    headless: true,
    proxy: {
      server: url.origin,
      username: decodeURIComponent(url.username),
      password: decodeURIComponent(url.password),
    },
  };
}
export class ClerkBrowser implements BrowserAdapter {
  constructor(private root: string) {}
  async open(
    project: string,
    p: Config["projects"][string],
  ): Promise<BrowserSession> {
    await privateDirectory(this.root);
    if (p.auth) return this.delegated(p);
    const state = join(this.root, project + ".json");
    const stat = await lstat(state);
    if (
      stat.isSymbolicLink() ||
      !stat.isFile() ||
      (process.platform !== "win32" && stat.mode & 0o077)
    )
      throw new Error("STATE_PERMISSIONS");
    const browser = await chromium.launch(chromiumLaunchOptions());
    let context: BrowserContext | undefined;
    try {
      context = await browser.newContext({
        storageState: state,
        serviceWorkers: "block",
        acceptDownloads: false,
      });
      // No external identity-provider requests are needed after enrollment. Block other origins.
      await context.route("**/*", async (route) => {
        const u = new URL(route.request().url());
        if (![p.origin, ...p.resourceOrigins].includes(u.origin))
          return route.abort();
        return route.continue();
      });
      const page = await context.newPage();
      page.setDefaultTimeout(10000);
      await page.goto(destination(p.origin, p.dashboardPath), {
        waitUntil: "domcontentloaded",
        timeout: 20000,
      });
      await page.waitForFunction(
        () =>
          !!(window as unknown as { Clerk?: { loaded: boolean } }).Clerk
            ?.loaded,
        {},
        { timeout: 15000 },
      );
      const ctx = context;
      return {
        identity: () => identity(page),
        run: async (steps: Step[]) => {
          for (const step of steps) {
            if (new URL(page.url()).origin !== p.origin)
              throw new Error("ORIGIN_DENIED");
            const loc = page.locator(step.selector);
            if (step.kind === "visible") {
              await loc.waitFor({ state: "visible" });
            } else if (step.kind === "click") await loc.click();
            else await loc.fill(step.value);
          }
        },
        close: async () => {
          await ctx.close();
          await browser.close();
        },
      };
    } catch {
      await context?.close().catch(() => {});
      await browser.close();
      throw new Error("BROWSER_SETUP_FAILED");
    }
  }
  private async delegated(
    p: Config["projects"][string],
  ): Promise<BrowserSession> {
    if (!p.auth) throw Error("DELEGATION_REQUIRED");
    const browser = await chromium.launch(chromiumLaunchOptions());
    let context: BrowserContext | undefined;
    let authenticated = false;
    try {
      context = await browser.newContext({
        serviceWorkers: "block",
        acceptDownloads: false,
      });
      const ctx = context;
      await ctx.route("**/*", async (route) => {
        const url = new URL(route.request().url());
        if (![p.origin, ...p.resourceOrigins].includes(url.origin))
          return route.abort();
        return route.continue();
      });
      const signed = await signSessionRequest(
        p.auth.identityFile,
        p.origin,
        p.auth.grantId,
      );
      const login = await ctx.request.post(p.origin + "/agentdoor/session", {
        data: signed,
        maxRedirects: 0,
        timeout: 15000,
      });
      if (login.status() !== 201) throw Error("LOGIN_DENIED");
      authenticated = true;
      const who = async () => {
        const r = await ctx.request.get(p.origin + "/agentdoor/identity", {
          maxRedirects: 0,
          timeout: 10000,
        });
        if (r.status() !== 200) return null;
        const data = await r.json();
        return data.grantId === p.auth?.grantId ? (data.userId ?? null) : null;
      };
      if ((await who()) !== p.accountId) throw Error("ACCOUNT_DENIED");
      const page = await ctx.newPage();
      page.setDefaultTimeout(10000);
      await page.goto(destination(p.origin, p.dashboardPath), {
        waitUntil: "domcontentloaded",
        timeout: 20000,
      });
      if (new URL(page.url()).origin !== p.origin) throw Error("ORIGIN_DENIED");
      return {
        remoteRevocation: true,
        identity: who,
        run: async (steps: Step[]) => {
          for (const step of steps) {
            if (new URL(page.url()).origin !== p.origin)
              throw Error("ORIGIN_DENIED");
            const loc = page.locator(step.selector);
            if (step.kind === "visible") {
              await loc.waitFor({ state: "visible" });
            } else if (step.kind === "click") await loc.click();
            else await loc.fill(step.value);
          }
          if (
            new URL(page.url()).origin !== p.origin ||
            (await who()) !== p.accountId
          )
            throw Error("ACCOUNT_DENIED");
        },
        close: async () => {
          await revokeAndClose({
            revoke: async () => {
              const revoked = await ctx.request.post(
                p.origin + "/agentdoor/revoke",
                { maxRedirects: 0, timeout: 10000 },
              );
              if (revoked.status() !== 200) throw Error("REMOTE_REVOCATION_FAILED");
            },
            closeContext: () => ctx.close(),
            closeBrowser: () => browser.close(),
          });
        },
      };
    } catch {
      let cleanupFailed = false;
      if (authenticated && context) {
        try {
          if (
            (
              await context.request.post(p.origin + "/agentdoor/revoke", {
                maxRedirects: 0,
                timeout: 10000,
              })
            ).status() !== 200
          )
            cleanupFailed = true;
        } catch {
          cleanupFailed = true;
        }
      }
      await context?.close().catch(() => {
        cleanupFailed = true;
      });
      await browser.close().catch(() => {
        cleanupFailed = true;
      });
      throw Error(
        cleanupFailed ? "START_FAILED_CLEANUP_FAILED" : "BROWSER_SETUP_FAILED",
      );
    }
  }
}
