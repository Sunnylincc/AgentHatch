import { randomUUID } from "node:crypto";
import type { Config } from "./config.js";
export interface BrowserSession {
  remoteRevocation?: boolean;
  identity(): Promise<string | null>;
  run(steps: Step[]): Promise<void>;
  close(): Promise<void>;
}
export type Step = Config["projects"][string]["tasks"][string]["steps"][number];
export interface BrowserAdapter {
  open(
    project: string,
    policy: Config["projects"][string],
  ): Promise<BrowserSession>;
}
type Session = {
  client: string;
  project: string;
  expires: number;
  state: "active" | "ended" | "cleanup_failed";
  browser: BrowserSession;
  timer: ReturnType<typeof setTimeout>;
};
export class AgentDoor {
  private sessions = new Map<string, Session>();
  private busy = false;
  constructor(
    private config: Config,
    private client: string,
    private browser: BrowserAdapter,
  ) {}
  list() {
    return Object.entries(this.config.projects)
      .filter(([, p]) => p.clients.includes(this.client))
      .map(([id, p]) => ({
        id,
        origin: p.origin,
        tasks: Object.keys(p.tasks),
        sessionSeconds: p.sessionSeconds,
      }));
  }
  async start(project: string) {
    const p = this.config.projects[project];
    if (!p || !p.clients.includes(this.client))
      throw new Error("ACCESS_DENIED");
    if (
      this.busy ||
      [...this.sessions.values()].filter((s) => s.state === "active").length >=
        4 ||
      this.sessions.size >= 100
    )
      throw new Error("RESOURCE_LIMIT");
    this.busy = true;
    let browser: BrowserSession | undefined;
    try {
      browser = await this.browser.open(project, p);
      if ((await browser.identity()) !== p.accountId)
        throw new Error("ACCOUNT_DENIED");
      const handle = randomUUID(),
        expires = Date.now() + p.sessionSeconds * 1000;
      const timer = setTimeout(() => {
        void this.end(handle).catch(() => {});
      }, p.sessionSeconds * 1000);
      timer.unref();
      this.sessions.set(handle, {
        client: this.client,
        project,
        expires,
        state: "active",
        browser,
        timer,
      });
      return this.status(handle);
    } catch {
      if (browser) {
        try {
          await browser.close();
        } catch {
          throw new Error("START_FAILED_CLEANUP_FAILED");
        }
      }
      throw new Error("START_FAILED");
    } finally {
      this.busy = false;
    }
  }
  private get(handle: string) {
    const s = this.sessions.get(handle);
    if (!s || s.client !== this.client) throw new Error("SESSION_NOT_FOUND");
    return s;
  }
  async status(handle: string) {
    const s = this.get(handle);
    if (s.state === "active" && Date.now() >= s.expires) await this.end(handle);
    return {
      handle,
      project: s.project,
      state: s.state,
      expiresAt: new Date(s.expires).toISOString(),
    };
  }
  async run(handle: string, task: string) {
    const s = this.get(handle);
    await this.status(handle);
    if (s.state !== "active") throw new Error("SESSION_INACTIVE");
    const p = this.config.projects[s.project];
    const t = p.tasks[task];
    if (!t) throw new Error("TASK_DENIED");
    if ((await s.browser.identity()) !== p.accountId) {
      await this.end(handle);
      throw new Error("ACCOUNT_DENIED");
    }
    await s.browser.run(t.steps);
    return { completed: true };
  }
  async end(handle: string) {
    const s = this.get(handle);
    clearTimeout(s.timer);
    if (s.state !== "ended") {
      try {
        await s.browser.close();
        s.state = "ended";
      } catch {
        s.state = "cleanup_failed";
      }
    }
    return {
      handle,
      state: s.state,
      remoteRevocation:
        s.state === "ended" && s.browser.remoteRevocation
          ? "confirmed"
          : "not_verified",
    };
  }
  async close() {
    return Promise.all([...this.sessions.keys()].map((h) => this.end(h)));
  }
}
