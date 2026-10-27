#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createInterface } from "node:readline/promises";
import { homedir } from "node:os";
import { resolve, join } from "node:path";
import { chmod, rename } from "node:fs/promises";
import { chromium } from "playwright";
import { initializeIdentity } from "./identity.js";
import { AgentDoor } from "./core.js";
import { ClerkBrowser, identity, privateDirectory } from "./browser.js";
import { loadConfig, destination } from "./config.js";
process.umask(0o077);
const [command, configPath, client, ...args] = process.argv.slice(2);
const handle = z.object({ handle: z.string().uuid() }).strict();
const inputs = {
  list_projects: z.object({}).strict(),
  start_test_session: z.object({ project: z.string().max(64) }).strict(),
  session_status: handle,
  end_test_session: handle,
  run_task: z
    .object({ handle: z.string().uuid(), task: z.string().max(64) })
    .strict(),
};
async function main() {
  if (command === "identity:init") {
    if (!configPath) throw Error("USAGE");
    const result = await initializeIdentity(resolve(configPath));
    process.stdout.write(
      JSON.stringify({ created: true, publicKeyFile: result.publicFile }) +
        "\n",
    );
    return;
  }
  if (!configPath || !client) throw new Error("USAGE");
  const config = await loadConfig(resolve(configPath));
  const root = join(homedir(), ".agentdoor");
  if (command === "enroll") {
    if (config.projects[args[0]]?.auth)
      throw Error("DELEGATED_PROJECT_NEEDS_NO_ENROLLMENT");
    if (!process.stdin.isTTY) throw new Error("INTERACTIVE_TERMINAL_REQUIRED");
    const project = args[0],
      p = config.projects[project];
    if (!p || !p.clients.includes(client)) throw new Error("ACCESS_DENIED");
    await privateDirectory(root);
    const browser = await chromium.launch({ headless: false });
    try {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(destination(p.origin, p.loginPath));
      const rl = createInterface({
        input: process.stdin,
        output: process.stderr,
      });
      try {
        await rl.question(
          "Sign in manually with the dedicated test account, then press Enter here. ",
        );
      } finally {
        rl.close();
      }
      if (
        new URL(page.url()).origin !== p.origin ||
        (await identity(page)) !== p.accountId
      )
        throw new Error("ACCOUNT_DENIED");
      const file = join(root, project + ".json");
      const temp = file + "." + crypto.randomUUID() + ".tmp";
      await context.storageState({ path: temp });
      await chmod(temp, 0o600);
      await rename(temp, file);
      process.stdout.write('{"enrolled":true}\n');
    } finally {
      await browser.close();
    }
    return;
  }
  const door = new AgentDoor(config, client, new ClerkBrowser(root));
  const dispatch = async (name: string, input: unknown) => {
    if (!(name in inputs)) throw new Error("COMMAND_DENIED");
    const data = (inputs as Record<string, z.ZodType>)[name].parse(
      input,
    ) as Record<string, string>;
    switch (name) {
      case "list_projects":
        return door.list();
      case "start_test_session":
        return door.start(data.project);
      case "session_status":
        return door.status(data.handle);
      case "end_test_session":
        return door.end(data.handle);
      case "run_task":
        return door.run(data.handle, data.task);
    }
  };
  const safe = async (name: string, input: unknown) => {
    try {
      return { ok: true, result: await dispatch(name, input) };
    } catch {
      return {
        ok: false,
        error: "REQUEST_FAILED",
        hint: "Check local configuration, enrollment, account permissions, task selectors, and session lifetime.",
      };
    }
  };
  const shutdown = async () => {
    await door.close();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
  if (command === "mcp") {
    const server = new McpServer({ name: "agentdoor", version: "0.2.0" });
    for (const [name, schema] of Object.entries(inputs))
      server.registerTool(
        name,
        { inputSchema: schema },
        async (input: unknown) => {
          const r = await safe(name, input);
          return {
            isError: !r.ok,
            content: [{ type: "text" as const, text: JSON.stringify(r) }],
          };
        },
      );
    await server.connect(new StdioServerTransport());
    process.stdin.on("end", () => {
      void shutdown();
    });
  } else if (command === "shell") {
    const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
    try {
      for await (const line of rl) {
        if (line.length > 8192) {
          process.stdout.write('{"ok":false,"error":"REQUEST_TOO_LARGE"}\n');
          continue;
        }
        try {
          const r = z
            .object({ command: z.string(), input: z.unknown().optional() })
            .strict()
            .parse(JSON.parse(line));
          process.stdout.write(
            JSON.stringify(await safe(r.command, r.input ?? {})) + "\n",
          );
        } catch {
          process.stdout.write('{"ok":false,"error":"INVALID_REQUEST"}\n');
        }
      }
    } finally {
      await door.close();
    }
  } else if (command === "list_projects") {
    process.stdout.write(JSON.stringify(await safe(command, {})) + "\n");
    await door.close();
  } else throw new Error("USAGE");
}
main().catch(() => {
  process.stderr.write(
    "AgentDoor failed. Usage: agentdoor <identity:init|enroll|shell|mcp|list_projects> <private-config.json> <configured-client> [project]. No upstream details are printed.\n",
  );
  process.exitCode = 1;
});
