import { DatabaseSync } from "node:sqlite";
import { normalizeOpenApi } from "@fungi.computer/forage/openapi";
import { fromNodeSqlite } from "@fungi.computer/watchdog/node-sqlite";
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vitest";
import {
  ConnectionsError,
  createConnections,
  type CustodyAdapter,
  type CustodyLookup,
} from "../src/connections/index.js";

const spec = JSON.stringify({
  openapi: "3.0.0",
  info: { title: "repos", version: "1" },
  servers: [{ url: "https://api.github.com" }],
  paths: {
    "/user": {
      get: {
        operationId: "getUser",
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: { login: { type: "string" } },
                  required: ["login"],
                  additionalProperties: false,
                },
              },
            },
          },
        },
      },
    },
  },
});

const run = <A>(effect: Effect.Effect<A, ConnectionsError>) =>
  Effect.runPromise(effect);
const code = async (promise: Promise<unknown>) => {
  try {
    await promise;
    return "ok";
  } catch (error) {
    return error instanceof ConnectionsError ? error.code : "unexpected";
  }
};

async function harness() {
  const sent: string[] = [];
  let lookup: CustodyLookup = { status: "unresolved" };
  const custody: CustodyAdapter = {
    put: () => Effect.fail(new ConnectionsError("unsupported")),
    inject: (_address, _locator, request) => {
      sent.push(request.url);
      return Effect.succeed(Response.json({ login: "octo" }));
    },
    remove: () => Effect.succeed("deleted"),
    find: () => Effect.succeed(lookup),
    connect: () =>
      Effect.succeed({
        connectUrl: "https://connect.example/?session_token=s1",
        expiresAt: 2_000_000,
      }),
  };
  const database = new DatabaseSync(":memory:");
  let counter = 0;
  const connections = createConnections({
    ownerId: "team-1",
    store: fromNodeSqlite(database),
    custody,
    custodyProviders: {
      "github-rest": { apiOrigins: ["https://api.github.com"] },
      "notion-mcp": { apiOrigins: ["https://mcp.notion.com"] },
    },
    authorize: (actor) => actor === "owner",
    clock: () => 1_000_000,
    ids: () => `id${String((counter += 1))}`,
  });
  const table = (await normalizeOpenApi(spec)).operations.filter(
    (operation) => operation.status === "supported",
  );
  let sequence = 0;
  const begin = (
    provider: string,
    baseUrl: string,
    requestId = `r${String((sequence += 1))}`,
  ) =>
    run(
      connections.begin("owner", {
        requestId,
        name: requestId,
        surface: { kind: "openapi", baseUrl, table },
        credential: { kind: "oauth", provider },
      }),
    );
  return {
    sent,
    database,
    connections,
    begin,
    find: (next: CustodyLookup) => {
      lookup = next;
    },
  };
}

describe("a custodian's credential goes only where its integration is pinned", () => {
  it("refuses an integration the host did not declare", async () => {
    const h = await harness();
    expect(await code(h.begin("github-git", "https://api.github.com"))).toBe(
      "invalid_input",
    );
    expect(await code(h.begin("anything", "https://api.github.com"))).toBe(
      "invalid_input",
    );
  });

  it("refuses another origin for a declared integration", async () => {
    const h = await harness();
    expect(await code(h.begin("github-rest", "https://evil.example/v1"))).toBe(
      "invalid_input",
    );
    expect((await run(h.connections.list("owner"))).length).toBe(0);
  });

  it("starts the pinned sign-in, and never sends to an origin it was not pinned to", async () => {
    const h = await harness();
    const started = await h.begin("github-rest", "https://api.github.com");
    expect(started.authorizeUrl).toContain("session_token=s1");
    await run(
      h.connections.completeCustody({
        state: started.attemptId ?? "",
        locator: "nango-1",
        principalId: "owner",
        integrationId: "github-rest",
      }),
    );
    const { grantVersion } = await run(
      h.connections.grant("owner", {
        connectionId: started.connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    const call = () =>
      run(
        h.connections.call(
          "agent-a",
          { connectionId: started.connectionId, grantVersion },
          { operation: "getUser", input: {} },
        ),
      );
    expect(await call()).toEqual({ login: "octo" });
    // Even if the stored destination were changed behind the core's back,
    // the credential is not sent.
    h.database
      .prepare(
        "UPDATE veil_connections SET surface = json_set(surface, '$.url', 'https://evil.example/v1') WHERE id = ?",
      )
      .run(started.connectionId);
    expect(await code(call())).not.toBe("ok");
    expect(h.sent).toEqual(["https://api.github.com/user"]);
  });

  it("settles a sign-in only for the principal who began it", async () => {
    const h = await harness();
    const started = await h.begin("github-rest", "https://api.github.com");
    expect(
      await code(
        run(
          h.connections.completeCustody({
            state: started.attemptId ?? "",
            locator: "nango-1",
            principalId: "someone-else",
            integrationId: "github-rest",
          }),
        ),
      ),
    ).toBe("denied");
    expect((await run(h.connections.list("owner")))[0]?.state).toBe("pending");
  });

  it("completes a sign-in whose signed completion never arrived", async () => {
    const h = await harness();
    const started = await h.begin("github-rest", "https://api.github.com");
    expect(h.connections.awaitingCustody()).toBe(1);
    expect(await run(h.connections.reconcilePending())).toEqual([]);
    h.find({ status: "ambiguous" });
    expect(await run(h.connections.reconcilePending())).toEqual([]);
    h.find({ status: "found", locator: "nango-1" });
    expect(await run(h.connections.reconcilePending())).toEqual([
      started.connectionId,
    ]);
    expect((await run(h.connections.list("owner")))[0]?.state).toBe("active");
    expect(h.connections.awaitingCustody()).toBe(0);
  });
});
