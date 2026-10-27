#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createInterface } from "node:readline/promises";
import { homedir } from "node:os";
import { resolve, join } from "node:path";
import { initializeIdentity, identityFingerprint } from "./identity.js";
import { probe } from "./probe.js";
import { AgentDoor } from "./core.js";
import { DelegatedBrowser } from "./browser.js";
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
  if (command === "probe" || command === "verify-config") {
    const p = config.projects[args[0]];
    if (!p || !p.clients.includes(client) || !p.auth || !p.expected || p.origin !== args[1]) throw Error("CONFIG_DENIED");
    if (await identityFingerprint(p.auth.identityFile) !== p.expected.fingerprint) throw Error("KEY_SUBSTITUTION_DENIED");
    if (command === "verify-config") process.stdout.write(JSON.stringify({verified:true,project:args[0],grantId:p.auth.grantId,accountId:p.accountId,fingerprint:p.expected.fingerprint,scopes:p.expected.scopes})+"\n");
    else process.stdout.write(JSON.stringify(await probe(p))+"\n");
    return;
  }

  const door = new AgentDoor(config, client, new DelegatedBrowser(root));
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
    const server = new McpServer({ name: "agenthatch", version: "0.3.0" });
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
    "AgentDoor failed. Usage: agentdoor <identity:init|verify-config|probe|shell|mcp|list_projects> <private-config.json> <configured-client> [project]. No upstream details are printed.\n",
  );
  process.exitCode = 1;
});
