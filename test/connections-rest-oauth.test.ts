import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { normalizeOpenApi } from "@fungi.computer/forage/openapi";
import { fromNodeSqlite } from "@fungi.computer/watchdog/node-sqlite";
import * as Effect from "effect/Effect";
import { describe, expect, it } from "vitest";
import {
  ConnectionsError,
  createConnections,
  createSealedCustody,
  type ConnectionDraft,
} from "../src/connections/index.js";

type Json = string | number | boolean | null | Json[] | { [key: string]: Json };
const callback = "https://hub.example.com/api/connections/callback";
const operatorSecret = "operator-app-secret";
const spec = JSON.stringify({
  openapi: "3.0.0",
  info: { title: "pets", version: "1" },
  servers: [{ url: "https://api.example.com/v1" }],
  paths: {
    "/pets": {
      get: {
        operationId: "listPets",
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: { pets: { type: "array", items: {} } },
                  required: ["pets"],
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

/** A REST provider with an authorization code flow and the API behind it, in process. */
function provider() {
  const codes = new Map<string, string>();
  const valid = new Set<string>();
  const refreshes = new Set<string>();
  const stats = { refreshes: 0, tokenRequests: 0 };
  let issued = 0;
  const json = (body: Json, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  const mint = () => {
    issued += 1;
    valid.add(`access-${String(issued)}`);
    refreshes.add(`refresh-${String(issued)}`);
    return {
      access_token: `access-${String(issued)}`,
      token_type: "Bearer",
      refresh_token: `refresh-${String(issued)}`,
      expires_in: 3600,
    };
  };
  const fetch = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.host === "api.example.com") {
      const bearer =
        request.headers.get("authorization")?.replace("Bearer ", "") ?? "";
      return valid.has(bearer)
        ? json({ pets: [] })
        : new Response("{}", { status: 401 });
    }
    if (url.host !== "login.example.com" || url.pathname !== "/token")
      return Promise.reject(new TypeError("no route"));
    stats.tokenRequests += 1;
    const form = new URLSearchParams(await request.text());
    if (
      form.get("client_id") !== "operator-app" ||
      form.get("client_secret") !== operatorSecret
    )
      return json({ error: "invalid_client" }, 401);
    if (form.get("grant_type") === "authorization_code") {
      const challenge = createHash("sha256")
        .update(form.get("code_verifier") ?? "")
        .digest("base64url");
      if (codes.get(form.get("code") ?? "") !== challenge)
        return json({ error: "invalid_grant" }, 400);
      return json(mint());
    }
    const held = form.get("refresh_token") ?? "";
    if (!refreshes.delete(held)) return json({ error: "invalid_grant" }, 400);
    stats.refreshes += 1;
    return json(mint());
  };
  return {
    fetch,
    stats,
    approve: (authorizeUrl: string) => {
      const query = new URL(authorizeUrl).searchParams;
      const code = `code-${query.get("state") ?? ""}`;
      codes.set(code, query.get("code_challenge") ?? "");
      return {
        state: query.get("state") ?? "",
        code,
        iss: "https://login.example.com",
      };
    },
    expireAccessTokens: () => {
      valid.clear();
    },
  };
}

function harness() {
  const remote = provider();
  const database = new DatabaseSync(":memory:");
  const vault = new Map<string, string>();
  let counter = 0;
  const connections = createConnections({
    ownerId: "team-1",
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
          return secret === undefined
            ? Promise.reject(
                Object.assign(new Error("absent"), { code: "absent" }),
              )
            : Promise.resolve(action(secret));
        },
        remove: (id) =>
          Promise.resolve(vault.delete(id) ? "deleted" : "absent"),
      },
      send: remote.fetch,
    }),
    authorize: (actor) => actor === "owner",
    oauth: {
      callbackUrl: callback,
      fetch: remote.fetch,
      providers: {
        acme: {
          issuer: "https://login.example.com",
          authorizationEndpoint: "https://login.example.com/authorize",
          tokenEndpoint: "https://login.example.com/token",
          scope: "pets.read",
          client: { client_id: "operator-app", client_secret: operatorSecret },
          apiOrigins: ["https://api.example.com"],
        },
      },
    },
    clock: () => 1_000_000,
    ids: () => `id${String((counter += 1))}`,
  });
  const run = <A>(effect: Effect.Effect<A, ConnectionsError>) =>
    Effect.runPromise(effect);
  const draft = async (
    requestId: string,
    over: Partial<ConnectionDraft> = {},
  ): Promise<ConnectionDraft> => ({
    requestId,
    name: `pets${requestId}`,
    surface: {
      kind: "openapi",
      baseUrl: "https://api.example.com/v1",
      table: (await normalizeOpenApi(spec)).operations.filter(
        (operation) => operation.status === "supported",
      ),
    },
    credential: { kind: "oauth", provider: "acme" },
    ...over,
  });
  return { remote, database, vault, connections, run, draft };
}
const code = (promise: Promise<unknown>) =>
  promise.then(
    () => "ok",
    (error: unknown) =>
      error instanceof ConnectionsError ? error.code : "other",
  );

describe("REST connections through an operator-registered provider", () => {
  it("sends a provider's token only to the API origins its operator declared", async () => {
    const h = harness();
    const elsewhere = await h.draft("r1");
    if (elsewhere.surface.kind !== "openapi") throw new Error("openapi draft");
    expect(
      await code(
        h.run(
          h.connections.begin("owner", {
            ...elsewhere,
            surface: {
              ...elsewhere.surface,
              baseUrl: "https://evil.example/v1",
            },
          }),
        ),
      ),
    ).toBe("invalid_input");
    expect(
      await code(
        h.run(
          h.connections.begin("owner", {
            ...(await h.draft("r2")),
            credential: { kind: "oauth", provider: "unregistered" },
          }),
        ),
      ),
    ).toBe("invalid_input");
    expect(h.remote.stats.tokenRequests).toBe(0);
  });

  it("signs in with the operator's client, calls with the token, and refreshes it", async () => {
    const h = harness();
    const started = await h.run(
      h.connections.begin("owner", await h.draft("r1")),
    );
    const url = new URL(started.authorizeUrl ?? "");
    expect(url.origin + url.pathname).toBe(
      "https://login.example.com/authorize",
    );
    expect(url.searchParams.get("client_id")).toBe("operator-app");
    expect(url.searchParams.get("scope")).toBe("pets.read");
    expect(url.searchParams.get("redirect_uri")).toBe(callback);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("state")?.startsWith("team-1.")).toBe(true);
    expect((await h.run(h.connections.list("owner")))[0]).toMatchObject({
      state: "pending",
      credentialKind: "oauth",
      surface: { kind: "openapi" },
    });
    await h.run(h.connections.complete("owner", h.remote.approve(url.href)));
    const { grantVersion } = await h.run(
      h.connections.grant("owner", {
        connectionId: started.connectionId,
        agentId: "agent-a",
        tools: { effect: "read" },
      }),
    );
    const ref = { connectionId: started.connectionId, grantVersion };
    const call = () =>
      h.run(
        h.connections.call("agent-a", ref, {
          operation: "listPets",
          input: {},
        }),
      );
    expect(await call()).toEqual({ pets: [] });
    // The access token expires at the provider: one refresh, then the call works.
    h.remote.expireAccessTokens();
    expect(await call()).toEqual({ pets: [] });
    expect(h.remote.stats.refreshes).toBe(1);
    const stored = JSON.stringify([
      ...h.vault.values(),
      h.database.prepare("SELECT * FROM veil_connections").all(),
    ]);
    // Tokens and the operator's secret live only sealed in custody.
    expect(stored).toContain("access-");
    const rows = JSON.stringify(
      h.database.prepare("SELECT * FROM veil_connections").all(),
    );
    expect(rows).not.toContain("access-");
    expect(rows).not.toContain(operatorSecret);
  });

  it("refuses a provider the host never registered, and a client the owner brings", async () => {
    const h = harness();
    for (const over of [
      { credential: { kind: "oauth", provider: "unknown" } } as const,
      {
        credential: { kind: "oauth", provider: "acme", clientId: "mine" },
      } as const,
      { credential: { kind: "oauth", provider: "acme" }, secret: "x" } as const,
      {
        credential: { kind: "oauth", provider: "acme" },
        surface: { kind: "mcp", url: "https://mcp.example.com/mcp" },
      } as const,
    ])
      expect(
        await code(
          h.run(h.connections.begin("owner", await h.draft("r2", over))),
        ),
      ).toBe("invalid_input");
  });

  it("rejects a sign-in return that was not begun here, or comes with a wrong issuer", async () => {
    const h = harness();
    const started = await h.run(
      h.connections.begin("owner", await h.draft("r3")),
    );
    const approval = h.remote.approve(started.authorizeUrl ?? "");
    expect(
      await code(
        h.run(h.connections.complete("owner", { ...approval, state: "x.y" })),
      ),
    ).not.toBe("ok");
    expect(
      await code(
        h.run(
          h.connections.complete("owner", {
            ...approval,
            iss: "https://evil.example.com",
          }),
        ),
      ),
    ).not.toBe("ok");
  });
});
