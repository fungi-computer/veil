import { createHmac } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { normalizeOpenApi } from "@fungi.computer/forage/openapi";
import { fromNodeSqlite } from "@fungi.computer/watchdog/node-sqlite";
import * as Effect from "effect/Effect";
import { z } from "zod";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ConnectionsError,
  createConnections,
  createSealedCustody,
  type CustodyAdapter,
  type CustodyAddress,
} from "../src/connections/index.js";
import { createNangoCustody } from "../src/connections/nango.js";

afterEach(() => vi.unstubAllGlobals());

const secret = "conformance-secret";
const address: CustodyAddress = {
  ownerId: "owner-1",
  connectionId: "conn-1",
  credential: { kind: "static", placement: "bearer" },
};
type Json = string | number | boolean | null | Json[] | { [key: string]: Json };
/** What the upstream API saw: where the request went and the credential it carried. */
type Seen = { url: string; authorization: string | null };

/** A custodian under test and the upstream whose requests it should deliver. */
type Subject = Readonly<{
  name: string;
  make: () => { custody: CustodyAdapter; seen: Seen[] };
}>;

const nangoOptions = {
  serverUrl: "https://nango.example",
  apiKey: "synthetic-host-key",
  webhookSigningKey: "synthetic-signing-key",
  staticIntegrationId: "api-key",
  connectBaseUrl: "https://connect.nango.example/",
  publicApiUrl: "https://api.nango.example",
} as const;

/** A disposable Nango: connection import and delete, Connect sessions and the proxy. */
function fakeNango(seen: Seen[]) {
  const held = new Map<string, { integration: string; credential: string }>();
  const json = (body: Json, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  const proxied: Headers[] = [];
  const fetch = async (input: string | URL | Request, init?: RequestInit) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (
      request.headers.get("authorization") !== `Bearer ${nangoOptions.apiKey}`
    )
      return json({ error: "unauthorized" }, 401);
    if (request.method === "POST" && url.pathname === "/connections") {
      const body = z
        .object({
          provider_config_key: z.string(),
          connection_id: z.string(),
          credentials: z.object({ apiKey: z.string() }),
        })
        .parse(await request.json());
      held.set(body.connection_id, {
        integration: body.provider_config_key,
        credential: body.credentials.apiKey,
      });
      return json({ connection_id: body.connection_id });
    }
    if (request.method === "POST" && url.pathname === "/connect/sessions")
      return json({
        data: {
          token: "session-1",
          connect_link:
            "https://connect.nango.example/?session_token=session-1",
          expires_at: new Date(2_000_000).toISOString(),
        },
      });
    if (
      request.method === "DELETE" &&
      url.pathname.startsWith("/connections/")
    ) {
      const id = decodeURIComponent(url.pathname.split("/")[2] ?? "");
      return held.delete(id)
        ? json({ success: true })
        : json({ error: { code: "unknown_connection" } }, 400);
    }
    if (url.pathname.startsWith("/proxy/")) {
      proxied.push(request.headers);
      const found = held.get(request.headers.get("connection-id") ?? "");
      if (found === undefined) return json({ error: "unknown" }, 404);
      seen.push({
        url:
          (request.headers.get("base-url-override") ?? "") +
          url.pathname.slice("/proxy".length) +
          url.search,
        authorization: `Bearer ${found.credential}`,
      });
      return json({ ok: true });
    }
    return json({ error: "no route" }, 404);
  };
  return { fetch, held, proxied };
}

const sealed: Subject = {
  name: "sealed",
  make: () => {
    const seen: Seen[] = [];
    const vault = new Map<string, string>();
    let counter = 0;
    return {
      seen,
      custody: createSealedCustody({
        vault: {
          put: ({ secret: value }) => {
            counter += 1;
            vault.set(`cred-${String(counter)}`, value);
            return Promise.resolve({ credentialId: `cred-${String(counter)}` });
          },
          withSecret: (id, action) => {
            const value = vault.get(id);
            return value === undefined
              ? Promise.reject(
                  Object.assign(new Error("absent"), { code: "absent" }),
                )
              : Promise.resolve(action(value));
          },
          remove: (id) =>
            Promise.resolve(vault.delete(id) ? "deleted" : "absent"),
        },
        send: (request) => {
          seen.push({
            url: request.url,
            authorization: request.headers.get("authorization"),
          });
          return Promise.resolve(Response.json({ ok: true }));
        },
      }),
    };
  },
};
const nango: Subject = {
  name: "nango",
  make: () => {
    const seen: Seen[] = [];
    vi.stubGlobal("fetch", fakeNango(seen).fetch);
    return { seen, custody: createNangoCustody(nangoOptions) };
  },
};

const run = <A>(effect: Effect.Effect<A, ConnectionsError>) =>
  Effect.runPromise(effect);
const code = (effect: Effect.Effect<unknown, ConnectionsError>) =>
  Effect.runPromise(
    Effect.match(effect, {
      onSuccess: () => "ok",
      onFailure: (error) => error.code,
    }),
  );

/** The laws every custodian keeps, whatever it stores and wherever it sends. */
describe.each([sealed, nango])("custody conformance: $name", (subject) => {
  it("keeps a credential it can use but never show", async () => {
    const { custody, seen } = subject.make();
    const locator = await run(custody.put(address, secret));
    expect(locator).not.toContain(secret);
    const response = await run(
      custody.inject(
        address,
        locator,
        new Request("https://api.example.com/v1/pets?limit=1"),
      ),
    );
    expect(await response.json()).toEqual({ ok: true });
    // Exactly one request left, to the destination asked for, carrying the credential.
    expect(seen).toEqual([
      {
        url: "https://api.example.com/v1/pets?limit=1",
        authorization: `Bearer ${secret}`,
      },
    ]);
  });

  it("refuses a locator it does not hold, and sends nothing", async () => {
    const { custody, seen } = subject.make();
    const refused = await code(
      custody.inject(
        address,
        "nobody",
        new Request("https://api.example.com/"),
      ),
    );
    expect(["reconnect_required", "unavailable"]).toContain(refused);
    expect(seen).toEqual([]);
  });

  it("removes once, reports absence after, and stops serving the credential", async () => {
    const { custody, seen } = subject.make();
    const locator = await run(custody.put(address, secret));
    expect(await run(custody.remove(address, locator))).toBe("deleted");
    expect(await run(custody.remove(address, locator))).toBe("absent");
    expect(
      await code(
        custody.inject(
          address,
          locator,
          new Request("https://api.example.com/"),
        ),
      ),
    ).not.toBe("ok");
    expect(seen).toEqual([]);
  });
});

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
                  properties: { ok: { type: "boolean" } },
                  required: ["ok"],
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
const signed = (body: string, key: string = nangoOptions.webhookSigningKey) =>
  createHmac("sha256", key).update(body).digest("hex");
const completion = (state: string, over: Record<string, Json> = {}) =>
  JSON.stringify({
    type: "auth",
    operation: "creation",
    success: true,
    connectionId: "nango-conn-9",
    providerConfigKey: "gh",
    tags: {
      veil_team_id: "owner-1",
      veil_attempt_id: state,
      veil_principal_id: "owner",
    },
    endUser: { endUserId: "owner", organizationId: "owner-1" },
    ...over,
  });

describe("an authorization Nango runs", () => {
  const pinned = { gh: { apiOrigins: ["https://api.example.com"] } } as const;
  async function connected(
    custodyProviders: Readonly<
      Record<string, { apiOrigins: readonly string[] }>
    > = pinned,
  ) {
    const seen: Seen[] = [];
    const remote = fakeNango(seen);
    vi.stubGlobal("fetch", remote.fetch);
    remote.held.set("nango-conn-9", {
      integration: "gh",
      credential: "oauth-token",
    });
    const custody = createNangoCustody(nangoOptions);
    const database = new DatabaseSync(":memory:");
    let counter = 0;
    const options = {
      ownerId: "owner-1",
      store: fromNodeSqlite(database),
      custody,
      authorize: (actor: string) => actor === "owner",
      clock: () => 1_000_000,
      ids: () => `id${String((counter += 1))}`,
    };
    const connections = createConnections({ ...options, custodyProviders });
    /** The same owner's store, served under another host declaration. */
    const reopened = (
      next: Readonly<Record<string, { apiOrigins: readonly string[] }>>,
    ) => createConnections({ ...options, custodyProviders: next });
    const started = await run(
      connections.begin("owner", {
        requestId: "r1",
        name: "pets",
        surface: {
          kind: "openapi",
          baseUrl: "https://api.example.com/v1",
          table: (await normalizeOpenApi(spec)).operations.filter(
            (operation) => operation.status === "supported",
          ),
        },
        credential: { kind: "oauth", provider: "gh" },
      }),
    );
    const state = `owner-1.id2`;
    return { seen, remote, custody, connections, reopened, started, state };
  }

  it("sends the owner to Connect, then activates only on a signed completion for that attempt", async () => {
    const h = await connected();
    expect(h.started.authorizeUrl).toContain("session_token=session-1");
    expect((await run(h.connections.list("owner")))[0]?.state).toBe("pending");

    const body = completion(h.state);
    // A wrong signature, a wrong integration and a foreign state are all refused.
    await expect(
      h.custody.verifyCompletion(body, signed(body, "other-key")),
    ).rejects.toBeInstanceOf(ConnectionsError);
    const verified = await h.custody.verifyCompletion(body, signed(body));
    expect(verified).toEqual({
      ownerId: "owner-1",
      state: h.state,
      locator: "nango-conn-9",
      principalId: "owner",
      integrationId: "gh",
    });
    expect(
      await code(
        h.connections.completeCustody({
          ...verified,
          integrationId: "other",
        }),
      ),
    ).toBe("denied");
  });

  it("serves the granted Agent through the proxy once settled, and the state is single use", async () => {
    const h = await connected();
    const verified = await h.custody.verifyCompletion(
      completion(h.state),
      signed(completion(h.state)),
    );
    await run(h.connections.completeCustody(verified));
    expect(await code(h.connections.completeCustody(verified))).toBe("denied");
    const { grantVersion } = await run(
      h.connections.grant("owner", {
        connectionId: h.started.connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    const result = await run(
      h.connections.call(
        "agent-a",
        { connectionId: h.started.connectionId, grantVersion },
        { operation: "listPets", input: {} },
      ),
    );
    expect(result).toEqual({ ok: true });
    expect(h.seen).toEqual([
      {
        url: "https://api.example.com/v1/pets",
        authorization: "Bearer oauth-token",
      },
    ]);
    expect(h.remote.proxied[0]?.get("provider-config-key")).toBe("gh");
  });

  it("pins each integration's credential to the origins the operator declared", async () => {
    const h = await connected();
    const table = (await normalizeOpenApi(spec)).operations.filter(
      (operation) => operation.status === "supported",
    );
    // Another origin, or an integration this host does not declare, never begins.
    for (const [requestId, baseUrl, provider] of [
      ["r2", "https://evil.example/v1", "gh"],
      ["r3", "https://api.example.com/v1", "undeclared"],
    ] as const)
      expect(
        await code(
          h.connections.begin("owner", {
            requestId,
            name: `pets${requestId}`,
            surface: { kind: "openapi", baseUrl, table },
            credential: { kind: "oauth", provider },
          }),
        ),
      ).toBe("invalid_input");
    const verified = await h.custody.verifyCompletion(
      completion(h.state),
      signed(completion(h.state)),
    );
    await run(h.connections.completeCustody(verified));
    const { grantVersion } = await run(
      h.connections.grant("owner", {
        connectionId: h.started.connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    const call = (connections: typeof h.connections) =>
      code(
        connections.call(
          "agent-a",
          { connectionId: h.started.connectionId, grantVersion },
          { operation: "listPets", input: {} },
        ),
      );
    // The pin is read again at send: a narrowed or withdrawn declaration
    // stops the credential before the custodian is asked to attach it.
    expect(
      await call(h.reopened({ gh: { apiOrigins: ["https://other.example"] } })),
    ).toBe("denied");
    expect(await call(h.reopened({}))).toBe("reconnect_required");
    expect(h.remote.proxied).toEqual([]);
    expect(await call(h.connections)).toBe("ok");
  });
});
