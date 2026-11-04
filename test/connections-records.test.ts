import { DatabaseSync } from "node:sqlite";
import { normalizeOpenApi } from "@fungi.computer/forage/openapi";
import { Mycelium } from "@fungi.computer/mycelium";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { directSandbox } from "@fungi.computer/mycelium/testing";
import { fromNodeSqlite } from "@fungi.computer/watchdog/node-sqlite";
import * as Effect from "effect/Effect";
import type * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import { describe, expect, it } from "vitest";
import { connectionsSource } from "../src/connections/source.js";
import {
  ConnectionsError,
  createConnections,
  createSealedCustody,
  type EgressRef,
  type Tools,
} from "../src/connections/index.js";

const base = "https://api.example.com/v1";
const marker = "records-secret-0123456789"; //gitleaks:allow
const pet = {
  type: "object",
  properties: { id: { type: "string" }, name: { type: "string" } },
  required: ["id", "name"],
  additionalProperties: false,
};
const spec = (extra = {}) =>
  JSON.stringify({
    openapi: "3.0.0",
    info: { title: "pets", version: "1" },
    servers: [{ url: base }],
    paths: {
      "/pets/{id}": {
        get: {
          operationId: "getPet",
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" },
            },
          ],
          responses: {
            "200": {
              description: "ok",
              content: { "application/json": { schema: pet } },
            },
          },
        },
      },
      "/pets": {
        post: {
          operationId: "createPet",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: { name: { type: "string" } },
                  required: ["name"],
                  additionalProperties: false,
                },
              },
            },
          },
          responses: {
            "200": {
              description: "ok",
              content: { "application/json": { schema: pet } },
            },
          },
        },
      },
      ...extra,
    },
  });
const table = async (source = spec()) =>
  (await normalizeOpenApi(source)).operations.filter(
    (operation) => operation.status === "supported",
  );

function harness() {
  const database = new DatabaseSync(":memory:");
  const vault = new Map<string, string>();
  const sent: Request[] = [];
  const checks: unknown[] = [];
  let counter = 0;
  let allowed = true;
  let reply = (request: Request): Response | Promise<Response> =>
    Response.json(
      request.method === "GET"
        ? { id: new URL(request.url).pathname.split("/").at(-1), name: "Rex" }
        : { id: "p1", name: "New" },
    );
  const connections = createConnections({
    ownerId: "owner-1",
    store: fromNodeSqlite(database),
    custody: createSealedCustody({
      vault: {
        put: ({ secret }) => {
          counter += 1;
          vault.set(`cred-${String(counter)}`, secret);
          return Promise.resolve({ credentialId: `cred-${String(counter)}` });
        },
        withSecret: (id, action) => {
          const secret = vault.get(id);
          if (secret === undefined) return Promise.reject(new Error("absent"));
          return Promise.resolve(action(secret));
        },
        remove: (id) =>
          Promise.resolve(vault.delete(id) ? "deleted" : "absent"),
      },
      send: (request) => {
        sent.push(request);
        return Promise.resolve(reply(request));
      },
    }),
    authorize: (actor) => actor === "owner",
    check: (grantor, grant, operation) => {
      checks.push({ grantor, agentId: grant.agentId, operation });
      return Promise.resolve(allowed);
    },
    clock: () => 1_000,
    ids: () => `id${String((counter += 1))}`,
  });
  const run = <A>(effect: Effect.Effect<A, ConnectionsError>) =>
    Effect.runPromise(effect);
  const connect = async (name = "pets", tools: Tools = "all") => {
    const { connectionId } = await run(
      connections.begin("owner", {
        requestId: `begin-${name}-${String((counter += 1))}`,
        name,
        surface: { kind: "openapi", baseUrl: base, table: await table() },
        credential: { kind: "static", placement: "bearer" },
        secret: marker,
      }),
    );
    const { grantVersion } = await run(
      connections.grant("owner", { connectionId, agentId: "agent-a", tools }),
    );
    return {
      connectionId,
      ref: { connectionId, grantVersion } satisfies EgressRef,
    };
  };
  return {
    database,
    vault,
    sent,
    checks,
    connections,
    run,
    connect,
    deny: () => {
      allowed = false;
    },
    reply: (next: (request: Request) => Response | Promise<Response>) => {
      reply = next;
    },
  };
}
const code = (effect: Effect.Effect<unknown, ConnectionsError>) =>
  Effect.runPromise(effect).then(
    () => "ok",
    (error: unknown) =>
      error instanceof ConnectionsError ? error.code : "other",
  );

describe("connection records", () => {
  it("updates against the version the owner saw and replays safely", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    const renamed = await h.run(
      h.connections.update("owner", {
        requestId: "u1",
        connectionId,
        expectedVersion: 1,
        name: "animals",
      }),
    );
    expect(renamed.version).toBe(2);
    const again = await h.run(
      h.connections.update("owner", {
        requestId: "u1",
        connectionId,
        expectedVersion: 1,
        name: "animals",
      }),
    );
    expect(again.version).toBe(2);
    expect(
      await code(
        h.connections.update("owner", {
          requestId: "u2",
          connectionId,
          expectedVersion: 1,
          name: "other",
        }),
      ),
    ).toBe("conflict");
    expect(
      await code(
        h.connections.update("owner", {
          requestId: "u1",
          connectionId,
          expectedVersion: 2,
          name: "different",
        }),
      ),
    ).toBe("conflict");
    const view = (await h.run(h.connections.list("owner")))[0];
    expect([view?.name, view?.version]).toEqual(["animals", 2]);
  });

  it("swaps the table and the credential, cleaning the old secret", async () => {
    const h = harness();
    const { connectionId, ref } = await h.connect();
    const before = (await h.run(h.connections.projection("agent-a")))
      .connections[0];
    const readOnly = (await table()).filter((op) => op.method === "GET");
    const next = await h.run(
      h.connections.update("owner", {
        requestId: "u1",
        connectionId,
        expectedVersion: 1,
        table: readOnly,
        credential: { kind: "static", placement: { header: "x-key" } },
        secret: "rotated-secret-abcdef",
      }),
    );
    expect(next.version).toBe(2);
    const after = (await h.run(h.connections.projection("agent-a")))
      .connections[0];
    expect(
      after?.surface.kind === "openapi" && before?.surface.kind === "openapi"
        ? after.surface.digest !== before.surface.digest
        : false,
    ).toBe(true);
    await h.run(
      h.connections.call("agent-a", ref, {
        operation: "getPet",
        input: { id: "7" },
      }),
    );
    expect(h.sent.at(-1)?.headers.get("x-key")).toBe("rotated-secret-abcdef");
    expect(h.sent.at(-1)?.headers.get("authorization")).toBeNull();
    await h.run(h.connections.sweep());
    expect([...h.vault.values()]).toEqual(["rotated-secret-abcdef"]);
    expect(
      await code(
        h.connections.call("agent-a", ref, {
          operation: "createPet",
          input: { body: { name: "x" } },
        }),
      ),
    ).toBe("denied");
    // A new destination may not inherit the sealed credential.
    expect(
      await code(
        h.connections.update("owner", {
          requestId: "u2",
          connectionId,
          expectedVersion: 2,
          baseUrl: "https://elsewhere.example.com/v1",
        }),
      ),
    ).toBe("invalid_input");
  });

  it("keeps one live binding name", async () => {
    const h = harness();
    const first = await h.connect("pets");
    await expect(h.connect("pets")).rejects.toMatchObject({ code: "conflict" });
    const second = await h.connect("birds");
    expect(
      await code(
        h.connections.update("owner", {
          requestId: "u",
          connectionId: second.connectionId,
          expectedVersion: 1,
          name: "pets",
        }),
      ),
    ).toBe("conflict");
    await h.run(
      h.connections.revoke("owner", { connectionId: first.connectionId }),
    );
    expect(
      (
        await h.run(
          h.connections.update("owner", {
            requestId: "u3",
            connectionId: second.connectionId,
            expectedVersion: 1,
            name: "pets",
          }),
        )
      ).version,
    ).toBe(2);
  });

  it("admits operations by stored effect, name or all", async () => {
    const h = harness();
    const { connectionId } = await h.connect("pets", { effect: "read" });
    const ref = (grantVersion: number) => ({ connectionId, grantVersion });
    const read = { operation: "getPet", input: { id: "1" } };
    const write = { operation: "createPet", input: { body: { name: "n" } } };
    expect(await h.run(h.connections.call("agent-a", ref(1), read))).toEqual({
      id: "1",
      name: "Rex",
    });
    expect(await code(h.connections.call("agent-a", ref(1), write))).toBe(
      "denied",
    );
    expect(h.sent).toHaveLength(1);
    // Raw egress cannot tell effects apart, so only an `all` grant may use it.
    const raw = h.connections.egress("agent-a", ref(1));
    await expect(
      raw(new Request(`${base}/pets/1`, { redirect: "error" })),
    ).rejects.toMatchObject({ code: "denied" });
    const named = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: ["createPet"],
      }),
    );
    expect(
      await code(h.connections.call("agent-a", ref(named.grantVersion), read)),
    ).toBe("denied");
    expect(
      await h.run(
        h.connections.call("agent-a", ref(named.grantVersion), write),
      ),
    ).toEqual({ id: "p1", name: "New" });
    const all = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    expect(
      (
        await h.connections.egress(
          "agent-a",
          ref(all.grantVersion),
        )(new Request(`${base}/pets/2`, { redirect: "error" }))
      ).status,
    ).toBe(200);
    // An effect grant means nothing on an MCP surface.
    await expect(
      h
        .run(
          h.connections.begin("owner", {
            requestId: "m",
            name: "mcp",
            surface: { kind: "mcp", url: "https://mcp.example.com/mcp" },
            credential: { kind: "none" },
          }),
        )
        .then(({ connectionId: id }) =>
          h.run(
            h.connections.grant("owner", {
              connectionId: id,
              agentId: "agent-a",
              tools: { effect: "read" },
            }),
          ),
        ),
    ).rejects.toMatchObject({ code: "invalid_input" });
  });

  it("asks the host before every send and honours its refusal", async () => {
    const h = harness();
    const { ref } = await h.connect();
    await h.run(
      h.connections.call("agent-a", ref, {
        operation: "createPet",
        input: { body: { name: "n" } },
      }),
    );
    expect(h.checks).toEqual([
      {
        grantor: "owner",
        agentId: "agent-a",
        operation: { name: "createPet", effect: "write" },
      },
    ]);
    h.deny();
    expect(
      await code(
        h.connections.call("agent-a", ref, {
          operation: "getPet",
          input: { id: "1" },
        }),
      ),
    ).toBe("denied");
    expect(h.sent).toHaveLength(1);
  });

  it("validates input and the upstream answer against the stored schemas", async () => {
    const h = harness();
    const { ref } = await h.connect();
    expect(
      await code(
        h.connections.call("agent-a", ref, {
          operation: "getPet",
          input: { id: 7 },
        }),
      ),
    ).toBe("invalid_input");
    expect(
      await code(
        h.connections.call("agent-a", ref, {
          operation: "getPet",
          input: { id: "../x" },
        }),
      ),
    ).toBe("invalid_input");
    expect(h.sent).toHaveLength(0);
    h.reply(() => Response.json({ id: "1", name: "Rex", secret: "extra" }));
    expect(
      await code(
        h.connections.call("agent-a", ref, {
          operation: "getPet",
          input: { id: "1" },
        }),
      ),
    ).toBe("invalid_response");
    h.reply(() => new Response("{}", { status: 500 }));
    expect(
      await code(
        h.connections.call("agent-a", ref, {
          operation: "getPet",
          input: { id: "1" },
        }),
      ),
    ).toBe("invalid_response");
    expect(
      await code(
        h.connections.call("agent-b", ref, {
          operation: "getPet",
          input: { id: "1" },
        }),
      ),
    ).toBe("revoked");
  });

  it("projects only the admitted operations as Mycelium modules", async () => {
    const h = harness();
    await h.connect("pets", { effect: "read" });
    const source = connectionsSource({
      id: "test-connections",
      read: () => Effect.runPromise(h.connections.projection("agent-a")),
      subscribe: () => () => undefined,
      call: (ref, operation, args) =>
        Effect.runPromise(
          h.connections.call("agent-a", ref, { operation, input: args }),
        ),
    });
    const acquired = await source.acquire({
      signal: new AbortController().signal,
      invalidate: () => undefined,
    });
    const seen: string[] = [];
    const answers = new Array<Schema.Json | undefined>();
    const runtime = await Mycelium.make({
      modules: acquired.snapshot.modules,
      sandbox: directSandbox(async (bindings) => {
        for (const operations of Object.values(bindings))
          seen.push(...Object.keys(operations));
        const getPet = Object.values(bindings)
          .map((operations) => operations.getPet)
          .find((candidate) => candidate !== undefined);
        answers.push(await getPet?.({ id: "9" }));
        return null;
      }),
    });
    const lease = await runtime.acquire();
    try {
      const prepared = await Effect.runPromise(
        lease.executeTool.prepare({
          type: "toolCall",
          id: "c",
          name: "execute",
          arguments: { code: "return 1" },
        }),
      );
      await Effect.runPromise(Stream.runCollect(prepared.execute()));
    } finally {
      await lease.release();
      await runtime.close();
      await acquired.release();
    }
    expect(seen).toContain("getPet");
    expect(seen).not.toContain("createPet");
    expect(answers[0]).toEqual({
      textSource: "third_party",
      value: { id: "9", name: "Rex" },
    });
  });

  it("lets the owner try an operation at the version they saw, without a grant", async () => {
    const h = harness();
    const { connectionId } = await h.connect();
    const view = (await h.run(h.connections.list("owner")))[0];
    expect(view?.label).toBe("pets");
    expect(view?.surface.digest).toMatch(/^[a-f0-9]{64}$/u);
    expect(view?.grants[0]?.grantor).toBe("owner");
    expect(
      (await h.run(h.connections.operations("owner", connectionId))).operations
        .map((op) => op.name)
        .sort(),
    ).toEqual(["createPet", "getPet"]);
    expect(view?.credential).toEqual({ kind: "static", placement: "bearer" });
    const probe = { operation: "getPet", input: { id: "3" } };
    expect(
      await h.run(
        h.connections.ownerCall(
          "owner",
          { connectionId, expectedVersion: 1 },
          probe,
        ),
      ),
    ).toEqual({ id: "3", name: "Rex" });
    expect(h.checks.at(-1)).toEqual({
      grantor: "owner",
      agentId: "owner:owner",
      operation: { name: "getPet", effect: "read" },
    });
    expect(
      await code(
        h.connections.ownerCall(
          "owner",
          { connectionId, expectedVersion: 9 },
          probe,
        ),
      ),
    ).toBe("conflict");
    expect(
      await code(
        h.connections.ownerCall(
          "stranger",
          { connectionId, expectedVersion: 1 },
          probe,
        ),
      ),
    ).toBe("denied");
    expect(h.connections.cleanupPending()).toBe(0);
    await h.run(h.connections.revoke("owner", { connectionId }));
    expect(
      await code(
        h.connections.ownerCall(
          "owner",
          { connectionId, expectedVersion: 1 },
          probe,
        ),
      ),
    ).toBe("revoked");
  });

  it("sends an unauthenticated connection without opening any credential", async () => {
    const h = harness();
    const { connectionId } = await h.run(
      h.connections.begin("owner", {
        requestId: "open-1",
        name: "open",
        surface: { kind: "openapi", baseUrl: base, table: await table() },
        credential: { kind: "none" },
      }),
    );
    const { grantVersion } = await h.run(
      h.connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    const ref = { connectionId, grantVersion };
    expect(
      await h.run(
        h.connections.call("agent-a", ref, {
          operation: "getPet",
          input: { id: "1" },
        }),
      ),
    ).toEqual({ id: "1", name: "Rex" });
    expect(h.sent.at(-1)?.headers.get("authorization")).toBeNull();
  });

  it("discards a response whose grant ended while the body streamed", async () => {
    const h = harness();
    const { connectionId, ref } = await h.connect();
    let release = () => undefined;
    const held = new Promise<void>((resolve) => {
      release = () => {
        resolve();
      };
    });
    let started = () => undefined;
    const begun = new Promise<void>((resolve) => {
      started = () => {
        resolve();
      };
    });
    h.reply(
      () =>
        new Response(
          new ReadableStream({
            async start(controller) {
              started();
              await held;
              controller.enqueue(
                new TextEncoder().encode('{"id":"1","name":"Rex"}'),
              );
              controller.close();
            },
          }),
        ),
    );
    const calling = code(
      h.connections.call("agent-a", ref, {
        operation: "getPet",
        input: { id: "1" },
      }),
    );
    await begun;
    await h.run(
      h.connections.ungrant("owner", { connectionId, agentId: "agent-a" }),
    );
    release();
    expect(await calling).toBe("revoked");
  });

  it("reports a connection whose projected table no longer matches its digest", async () => {
    const h = harness();
    await h.connect();
    const skipped: string[] = [];
    const source = connectionsSource({
      id: "test-connections",
      onSkipped: (id) => skipped.push(id),
      read: async () => {
        const projection = await Effect.runPromise(
          h.connections.projection("agent-a"),
        );
        return {
          ...projection,
          connections: projection.connections.map((connection) =>
            connection.surface.kind === "openapi"
              ? {
                  ...connection,
                  surface: { ...connection.surface, digest: "0".repeat(64) },
                }
              : connection,
          ),
        };
      },
      subscribe: () => () => undefined,
      call: () => Promise.reject(new Error("not called")),
    });
    const acquired = await source.acquire({
      signal: new AbortController().signal,
      invalidate: () => undefined,
    });
    expect(acquired.snapshot.modules).toEqual([]);
    expect(skipped).toHaveLength(1);
    await acquired.release();
  });

  it("calls the store's transaction as a method, as a Durable Object requires", async () => {
    const database = new DatabaseSync(":memory:");
    const inner = fromNodeSqlite(database);
    // Like Cloudflare storage: the method refuses to run detached from its owner.
    class BoundStore {
      readonly #owner = inner;
      readonly sql = inner.sql;
      transactionSync<A>(body: () => A): A {
        return this.#owner.transactionSync(body);
      }
    }
    const connections = createConnections({
      ownerId: "owner-1",
      store: new BoundStore(),
      custody: createSealedCustody({
        vault: {
          put: () => Promise.resolve({ credentialId: "c" }),
          withSecret: (_id, action) => Promise.resolve(action("s")),
          remove: () => Promise.resolve("deleted"),
        },
        send: () => Promise.resolve(Response.json({})),
      }),
      authorize: (actor) => actor === "owner",
      clock: () => 1_000,
      ids: () => "id1",
    });
    const { connectionId } = await Effect.runPromise(
      connections.begin("owner", {
        requestId: "bound-1",
        name: "bound",
        surface: { kind: "mcp", url: "https://mcp.example.com/mcp" },
        credential: { kind: "none" },
      }),
    );
    await Effect.runPromise(
      connections.grant("owner", {
        connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    await Effect.runPromise(connections.sweep());
    database.close();
  });

  it("lists an MCP connection's tools for its owner only", async () => {
    const h = harness();
    const handler = createMcpHandler(() => {
      const server = new McpServer({ name: "fixture", version: "1" });
      for (const name of ["alpha", "beta"])
        server.registerTool(
          name,
          { description: name, inputSchema: z.object({}) },
          () => ({ content: [{ type: "text", text: name }] }),
        );
      return server;
    });
    h.reply((request) => handler.fetch(request));
    const { connectionId } = await h.run(
      h.connections.begin("owner", {
        requestId: "mcp-1",
        name: "mcp",
        surface: { kind: "mcp", url: "https://mcp.example.com/mcp" },
        credential: { kind: "none" },
      }),
    );
    expect(await h.run(h.connections.tools("owner", connectionId))).toEqual([
      "alpha",
      "beta",
    ]);
    expect(await code(h.connections.tools("stranger", connectionId))).toBe(
      "denied",
    );
  });
});
