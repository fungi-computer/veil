import { DatabaseSync } from "node:sqlite";
import * as Effect from "effect/Effect";
import { normalizeOpenApi } from "@fungi.computer/forage/openapi";
import { fromNodeSqlite } from "@fungi.computer/watchdog/node-sqlite";
import { describe, expect, it } from "vitest";
import {
  ConnectionsError,
  createConnections,
  createSealedCustody,
  type CustodyAdapter,
  type NarrowFetch,
} from "../src/connections/index.js";

const marker = "marker-secret-0123456789abcdef"; //gitleaks:allow
const mcpUrl = "https://mcp.example.com/mcp";
const jsonRpc = (method: string, params?: { name: string }) =>
  JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
const post = (body: string, init: RequestInit = {}) =>
  new Request(mcpUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
    redirect: "error",
    ...init,
  });

/** Test custody only: keeps secrets in memory and sends through a fake upstream. */
function testCustody(upstream: (request: Request) => Response) {
  const secrets = new Map<string, string>();
  const removed: string[] = [];
  let failRemove = 0;
  let reconnect = false;
  const sent: Request[] = [];
  const custody: CustodyAdapter = {
    put: (address, secret) =>
      Effect.sync(() => {
        const locator = `loc-${address.connectionId}`;
        secrets.set(locator, secret);
        return locator;
      }),
    inject: (address, locator, request) =>
      Effect.suspend(() => {
        if (reconnect)
          return Effect.fail(new ConnectionsError("reconnect_required"));
        const secret = secrets.get(locator);
        if (secret === undefined)
          return Effect.fail(new ConnectionsError("denied"));
        const headers = new Headers(request.headers);
        if (
          address.credential.kind === "static" &&
          address.credential.placement === "bearer"
        )
          headers.set("authorization", `Bearer ${secret}`);
        const forwarded = new Request(request, { headers });
        sent.push(forwarded);
        return Effect.succeed(upstream(forwarded));
      }),
    remove: (_address, locator) =>
      Effect.suspend(() => {
        if (failRemove > 0) {
          failRemove -= 1;
          return Effect.fail(new ConnectionsError("unavailable"));
        }
        removed.push(locator);
        return Effect.succeed(
          secrets.delete(locator) ? ("deleted" as const) : ("absent" as const),
        );
      }),
  };
  return {
    custody,
    secrets,
    removed,
    sent,
    failRemoves: (n: number) => (failRemove = n),
    needReconnect: () => (reconnect = true),
  };
}

function harness(
  upstream: (request: Request) => Response = () => Response.json({ ok: true }),
) {
  const database = new DatabaseSync(":memory:");
  const authority = new Set(["owner"]);
  let tick = 0;
  const fake = testCustody(upstream);
  const connections = createConnections({
    ownerId: "owner-1",
    store: fromNodeSqlite(database),
    custody: fake.custody,
    authorize: (actor) => authority.has(actor),
    clock: () => 1_000,
    ids: () => `id-${String((tick += 1))}`,
  });
  const run = <A>(effect: Effect.Effect<A, ConnectionsError>) =>
    Effect.runPromise(effect);
  const connect = (requestId = "req-1") =>
    run(
      connections.begin("owner", {
        requestId,
        name: "Docs",
        surface: { kind: "mcp", url: mcpUrl },
        credential: { kind: "static", placement: "bearer" },
        secret: marker,
      }),
    );
  return { database, authority, connections, run, connect, ...fake };
}
const code = (promise: Promise<unknown>) =>
  promise.then(
    () => "ok",
    (error: unknown) =>
      error instanceof ConnectionsError ? error.code : "other",
  );
const call = (fetch: NarrowFetch, tool: string) =>
  fetch(post(jsonRpc("tools/call", { name: tool })));

describe("sealed custody", () => {
  it("seals through the vault and releases the secret only into the send", async () => {
    const stored = new Map<string, string>();
    const sent: Request[] = [];
    const custody = createSealedCustody({
      vault: {
        put: ({ secret }) => {
          stored.set("cred-1", secret);
          return Promise.resolve({ credentialId: "cred-1" });
        },
        withSecret: (id, action) => {
          const secret = stored.get(id);
          if (secret === undefined)
            return Promise.reject(
              Object.assign(new Error("absent"), { code: "absent" }),
            );
          return Promise.resolve(action(secret));
        },
        remove: (id) =>
          Promise.resolve(stored.delete(id) ? "deleted" : "absent"),
      },
      send: (request) => {
        sent.push(request);
        return Promise.resolve(Response.json({}));
      },
    });
    const address = {
      ownerId: "o",
      connectionId: "c",
      credential: { kind: "static", placement: { query: "key" } },
    } as const;
    const locator = await Effect.runPromise(custody.put(address, marker));
    await Effect.runPromise(
      custody.inject(
        address,
        locator,
        new Request(mcpUrl, { redirect: "error" }),
      ),
    );
    expect(new URL(sent[0]?.url ?? "").searchParams.get("key")).toBe(marker);
    expect(await Effect.runPromise(custody.remove(address, locator))).toBe(
      "deleted",
    );
    await expect(
      Effect.runPromise(custody.inject(address, locator, new Request(mcpUrl))),
    ).rejects.toMatchObject({ code: "reconnect_required" });
  });
});

describe("openapi surface", () => {
  it("stays inside its base path and projects the decoded table", async () => {
    const preview = await normalizeOpenApi(
      JSON.stringify({
        openapi: "3.0.0",
        info: { title: "t", version: "1" },
        servers: [{ url: "https://api.example.com/v1" }],
        paths: {
          "/ping": {
            get: {
              operationId: "ping",
              responses: { "200": { description: "ok" } },
            },
          },
        },
      }),
    );
    const table = preview.operations.filter((op) => op.status === "supported");
    expect(table).toHaveLength(1);
    const h = harness();
    const { connectionId } = await h.run(
      h.connections.begin("owner", {
        requestId: "req-api",
        name: "API",
        surface: {
          kind: "openapi",
          baseUrl: "https://api.example.com/v1",
          table,
        },
        credential: { kind: "static", placement: { header: "x-api-key" } },
        secret: marker,
      }),
    );
    const { grantVersion } = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    const fetch = h.connections.egress("agent-a", {
      connectionId,
      grantVersion,
    });
    const get = (url: string) => fetch(new Request(url, { redirect: "error" }));
    expect((await get("https://api.example.com/v1/ping")).status).toBe(200);
    expect(await code(get("https://api.example.com/v2/ping"))).toBe("denied");
    expect(await code(get("https://api.example.com/v1evil/ping"))).toBe(
      "denied",
    );
    const upload = (bytes: Uint8Array) =>
      fetch(
        new Request("https://api.example.com/v1/ping", {
          method: "POST",
          body: bytes,
          headers: { "content-type": "application/octet-stream" },
          redirect: "error",
        }),
      );
    const binary = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect((await upload(binary)).status).toBe(200);
    expect(
      new Uint8Array(
        (await h.sent.at(-1)?.arrayBuffer()) ?? new ArrayBuffer(0),
      ),
    ).toEqual(binary);
    expect((await upload(new Uint8Array(256 * 1024))).status).toBe(200);
    expect(await code(upload(new Uint8Array(256 * 1024 + 1)))).toBe(
      "too_large",
    );
    const projected = (await h.run(h.connections.projection("agent-a")))
      .connections[0];
    expect(projected?.surface.kind).toBe("openapi");
    expect(JSON.stringify(projected)).not.toContain(marker);
  });
});

describe("connections core", () => {
  it("grants one Agent and refuses another", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    const { grantVersion } = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    const response = await call(
      h.connections.egress("agent-a", { connectionId, grantVersion }),
      "anything",
    );
    expect(response.status).toBe(200);
    expect(h.sent[0]?.headers.get("authorization")).toBe(`Bearer ${marker}`);
    expect(
      await code(
        call(
          h.connections.egress("agent-b", { connectionId, grantVersion }),
          "anything",
        ),
      ),
    ).toBe("revoked");
  });

  it("refuses the next call once the connection is revoked and deletes custody", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    const { grantVersion } = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    const fetch = h.connections.egress("agent-a", {
      connectionId,
      grantVersion,
    });
    expect((await call(fetch, "t")).status).toBe(200);
    await h.run(h.connections.revoke("owner", { connectionId }));
    expect(await code(call(fetch, "t"))).toBe("revoked");
    expect(h.secrets.size).toBe(0);
    expect(h.removed).toEqual([`loc-${connectionId}`]);
  });

  it("refuses the next call after ungrant and after the grantor loses authority", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    const { grantVersion } = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    const fetch = h.connections.egress("agent-a", {
      connectionId,
      grantVersion,
    });
    h.authority.delete("owner");
    expect(await code(call(fetch, "t"))).toBe("denied");
    h.authority.add("owner");
    await h.run(
      h.connections.ungrant("owner", { connectionId, agentId: "agent-a" }),
    );
    expect(await code(call(fetch, "t"))).toBe("revoked");
  });

  it("refuses a stale grant version once the owner narrows the grant", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    const wide = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    const stale = h.connections.egress("agent-a", {
      connectionId,
      grantVersion: wide.grantVersion,
    });
    const narrow = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: ["search"],
      }),
    );
    expect(await code(call(stale, "search"))).toBe("revoked");
    const fresh = h.connections.egress("agent-a", {
      connectionId,
      grantVersion: narrow.grantVersion,
    });
    expect((await call(fresh, "search")).status).toBe(200);
  });

  it("keeps secret bytes out of the projection, the listing and the database", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: ["search"],
      }),
    );
    const projection = await h.run(h.connections.projection("agent-a"));
    expect(projection.connections).toHaveLength(1);
    expect(JSON.stringify(projection)).not.toContain(marker);
    expect(
      JSON.stringify(await h.run(h.connections.list("owner"))),
    ).not.toContain(marker);
    const dump = JSON.stringify(
      [
        "veil_connections",
        "veil_connection_attempts",
        "veil_connection_grants",
        "veil_connection_receipts",
      ].map((table) => h.database.prepare(`SELECT * FROM ${table}`).all()),
    );
    expect(dump).not.toContain(marker);
    expect(
      (await h.run(h.connections.projection("agent-b"))).connections,
    ).toEqual([]);
  });

  it("refuses redirects, cross-origin and off-endpoint requests", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    const { grantVersion } = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    const fetch = h.connections.egress("agent-a", {
      connectionId,
      grantVersion,
    });
    const body = jsonRpc("tools/list");
    expect(await code(fetch(post(body, { redirect: "follow" })))).toBe(
      "denied",
    );
    expect(
      await code(
        fetch(
          new Request("https://evil.example.net/mcp", {
            method: "POST",
            body,
            redirect: "error",
          }),
        ),
      ),
    ).toBe("denied");
    expect(
      await code(
        fetch(
          new Request("https://mcp.example.com/other", {
            method: "POST",
            body,
            redirect: "error",
          }),
        ),
      ),
    ).toBe("denied");
    expect(
      await code(
        fetch(
          post(body, {
            headers: {
              authorization: "Bearer mine",
              "content-type": "application/json",
            },
          }),
        ),
      ),
    ).toBe("denied");
    expect(h.sent).toHaveLength(0);
  });

  it("refuses a redirect answer from the upstream", async () => {
    const h = harness(
      () =>
        new Response(null, {
          status: 302,
          headers: { location: "https://evil.example.net/" },
        }),
    );
    const { connectionId } = await h.connect();
    const { grantVersion } = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    expect(
      await code(
        call(
          h.connections.egress("agent-a", { connectionId, grantVersion }),
          "t",
        ),
      ),
    ).toBe("invalid_response");
  });

  it("refuses non-public destinations at connect", async () => {
    const h = harness();
    const refused = h.run(
      h.connections.begin("owner", {
        requestId: "req-private",
        name: "Local",
        surface: { kind: "mcp", url: "https://127.0.0.1/mcp" },
        credential: { kind: "none" },
      }),
    );
    await expect(refused).rejects.toMatchObject({ code: "denied" });
  });

  it("replays connect and grant idempotently", async () => {
    const h = harness();
    const first = await h.connect("req-1");
    const second = await h.connect("req-1");
    expect(second.connectionId).toBe(first.connectionId);
    expect(h.secrets.size).toBe(1);
    expect(await h.run(h.connections.list("owner"))).toHaveLength(1);
    const g1 = await h.run(
      h.connections.grant("owner", {
        connectionId: first.connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    const g2 = await h.run(
      h.connections.grant("owner", {
        connectionId: first.connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    expect(g2.grantVersion).toBe(g1.grantVersion);
    const narrowed = await h.run(
      h.connections.grant("owner", {
        connectionId: first.connectionId,
        agentId: "agent-a",
        tools: ["x"],
      }),
    );
    expect(narrowed.grantVersion).toBe(g1.grantVersion + 1);
    await expect(
      h.run(
        h.connections.begin("owner", {
          requestId: "req-1",
          name: "Other",
          surface: { kind: "mcp", url: mcpUrl },
          credential: { kind: "static", placement: "bearer" },
          secret: marker,
        }),
      ),
    ).rejects.toMatchObject({ code: "conflict" });
  });

  it("refuses a tool outside a listed grant, decoding JSON-RPC with the SDK", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    const { grantVersion } = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: ["search"],
      }),
    );
    const fetch = h.connections.egress("agent-a", {
      connectionId,
      grantVersion,
    });
    expect((await call(fetch, "search")).status).toBe(200);
    expect((await fetch(post(jsonRpc("tools/list")))).status).toBe(200);
    expect(await code(call(fetch, "delete_everything"))).toBe("denied");
    expect(await code(fetch(post("[{}]")))).toBe("denied");
    expect(await code(fetch(post("not json")))).toBe("denied");
    expect(h.sent).toHaveLength(2);
  });

  it("allows every tool, including future ones, when the grant is all", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    const { grantVersion } = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    expect(
      (
        await call(
          h.connections.egress("agent-a", { connectionId, grantVersion }),
          "added_tomorrow",
        )
      ).status,
    ).toBe(200);
  });

  it("marks reconnect-required when custody asks and refuses until then", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    const { grantVersion } = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    const fetch = h.connections.egress("agent-a", {
      connectionId,
      grantVersion,
    });
    expect((await call(fetch, "t")).status).toBe(200);
    h.needReconnect();
    expect(await code(call(fetch, "t"))).toBe("reconnect_required");
    expect(await code(call(fetch, "t"))).toBe("reconnect_required");
    expect((await h.run(h.connections.list("owner")))[0]?.state).toBe(
      "reconnect_required",
    );
    expect(
      (await h.run(h.connections.projection("agent-a"))).connections,
    ).toEqual([]);
  });

  it("retries custody cleanup a bounded number of times", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    h.failRemoves(2);
    await h.run(h.connections.revoke("owner", { connectionId }));
    expect(h.removed).toEqual([]);
    await h.run(h.connections.sweep());
    expect(h.removed).toEqual([]);
    await h.run(h.connections.sweep());
    expect(h.removed).toEqual([`loc-${connectionId}`]);
    expect(
      h.database
        .prepare("SELECT COUNT(*) AS n FROM veil_connection_cleanup")
        .get(),
    ).toEqual({ n: 0 });
  });

  it("keeps exhausted custody cleanup pending without retrying forever", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    h.failRemoves(5);
    await h.run(h.connections.revoke("owner", { connectionId }));
    for (let attempt = 1; attempt < 5; attempt += 1)
      await h.run(h.connections.sweep());
    expect(h.connections.cleanupPending()).toBe(1);
    expect(h.connections.cleanupRetryPending()).toBe(0);
    await h.run(h.connections.sweep());
    expect(h.secrets.size).toBe(1);
    expect(h.removed).toEqual([]);
  });

  it("refuses management by an unauthorized actor", async () => {
    const h = harness();
    await expect(
      h.run(
        h.connections.begin("stranger", {
          requestId: "r",
          name: "x",
          surface: { kind: "mcp", url: mcpUrl },
          credential: { kind: "none" },
        }),
      ),
    ).rejects.toMatchObject({ code: "denied" });
  });
});
