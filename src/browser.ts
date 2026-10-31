import { chromium, type BrowserContext, type Page } from "playwright";
import { mkdir, chmod, lstat } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "./config.js";
import { chromiumProxy } from "./proxy.js";
import { runSteps } from "./task-runner.js";
import { identityFingerprint, signSessionRequest } from "./identity.js";
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
export class DelegatedBrowser implements BrowserAdapter {
  constructor(private root: string) {}
  async open(
    project: string,
    p: Config["projects"][string],
  ): Promise<BrowserSession> {
    if (!p.auth) throw Error("DELEGATION_REQUIRED");
    return this.delegated(p);
  }
  private async delegated(
    p: Config["projects"][string],
  ): Promise<BrowserSession> {
    if (!p.auth) throw Error("DELEGATION_REQUIRED");
    if (p.expected && await identityFingerprint(p.auth.identityFile) !== p.expected.fingerprint) throw Error("KEY_SUBSTITUTION_DENIED");
    const browser = await chromium.launch({ headless: true, proxy: chromiumProxy() });
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
        if (p.expected && (data.fingerprint !== p.expected.fingerprint || data.agentId !== p.expected.agentId || data.paidModelCapMicrousd !== 0 || JSON.stringify([...(data.scopes ?? [])].sort()) !== JSON.stringify([...p.expected.scopes].sort()))) return null;
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
          await runSteps(page, steps, p.origin);
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
