// Local integration fixture, not a hosted product or production session store.
import { createServer } from "node:http";
import { readFile, lstat } from "node:fs/promises";
import { createDelegation, MemoryDelegationStore } from "../dist/delegation.js";
const file = process.env.AGENTDOOR_GRANTS_FILE;
if (!file)
  throw Error(
    "Set AGENTDOOR_GRANTS_FILE to an owner-managed grants JSON file.",
  );
let origin = "",
  sdk;
const notes = new Map();
const escape = (s) =>
  String(s).replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const server = createServer(async (req, res) => {
  try {
    let length = 0;
    const chunks = [];
    for await (const chunk of req) {
      length += chunk.length;
      if (length > 8192) {
        res.writeHead(413);
        res.end();
        return;
      }
      chunks.push(chunk);
    }
    const request = new Request(origin + req.url, {
      method: req.method,
      headers: req.headers,
      ...(chunks.length ? { body: Buffer.concat(chunks) } : {}),
    });
    let response;
    if (req.url.startsWith("/agentdoor/")) response = await sdk.handle(request);
    else if (req.url === "/dashboard" && req.method === "GET") {
      const p = await sdk.authorize(request, "notes:read");
      response = new Response(
        `<main><h1>Agent workspace</h1><p id="identity">${escape(p.userId)}</p><p data-note="true">${escape(notes.get(p.userId) || "No note")}</p><form method="POST" action="/note"><label>Test note<textarea name="note"></textarea></label><button>Save test note</button></form></main>`,
        {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "Content-Security-Policy":
              "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
          },
        },
      );
    } else if (req.url === "/note" && req.method === "POST") {
      const p = await sdk.authorize(request, "notes:write");
      const value = new URLSearchParams(Buffer.concat(chunks).toString()).get(
        "note",
      );
      if (!value || value.length > 500) throw Error("INVALID_NOTE");
      notes.set(p.userId, value);
      response = new Response(null, {
        status: 303,
        headers: { Location: "/dashboard" },
      });
    } else response = new Response("Not found", { status: 404 });
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(await response.text());
  } catch {
    res.writeHead(403, { "Cache-Control": "no-store" });
    res.end("Access denied");
  }
});
server.listen(Number(process.env.PORT ?? 0), "127.0.0.1", () => {
  origin = `http://127.0.0.1:${server.address().port}`;
  sdk = createDelegation({
    origin,
    allowLocalHttp: true,
    store: new MemoryDelegationStore(),
    getGrant: async (id) => {
      const stat = await lstat(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536)
        throw Error("GRANTS_FILE_DENIED");
      const grants = JSON.parse(await readFile(file, "utf8"));
      return grants.find((g) => g.id === id) ?? null;
    },
  });
  process.stdout.write(JSON.stringify({ origin }) + "\n");
});
