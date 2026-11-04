import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { fromNodeSqlite } from "@fungi.computer/watchdog/node-sqlite";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  ConnectionsError,
  createConnections,
  createSealedCustody,
  type NarrowFetch,
} from "../src/connections/index.js";

const mcp = "https://mcp.example.com/mcp";
const callback = "https://oyster.example.com/api/connections/callback";
const clientSecret = "byo-client-secret-0123456789"; //gitleaks:allow

type Json = string | number | boolean | null | Json[] | { [key: string]: Json };
type Code = { challenge: string; clientId: string };

/** An OAuth authorization server and an MCP resource server, in process. */
function world() {
  const clients = new Map<string, { secret?: string }>();
  const codes = new Map<string, Code>();
  const valid = new Set<string>();
  const refreshes = new Map<string, string>();
  const stats = {
    registrations: 0,
    refreshes: 0,
    tokenSecrets: new Array<string>(),
  };
  let issued = 0;
  let gate: Promise<void> | undefined;
  let tokenLife = 3600;
  const mint = (clientId: string) => {
    issued += 1;
    const access = `access-${String(issued)}`;
    const refresh = `refresh-${String(issued)}`;
    valid.add(access);
    refreshes.set(refresh, clientId);
    return {
      access_token: access,
      token_type: "Bearer",
      refresh_token: refresh,
      expires_in: tokenLife,
    };
  };
  const handler = createMcpHandler(() => {
    const server = new McpServer({ name: "fixture", version: "1" });
    server.registerTool(
      "ping",
      { description: "Ping.", inputSchema: z.object({}) },
      () => ({
        content: [{ type: "text", text: "pong" }],
      }),
    );
    return server;
  });
  const json = (body: Json, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  const fetch = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.host === "mcp.example.com") {
      if (url.pathname.startsWith("/.well-known/oauth-protected-resource"))
        return json({
          resource: mcp,
          authorization_servers: ["https://auth.example.com"],
        });
      const bearer =
        request.headers.get("authorization")?.replace("Bearer ", "") ?? "";
      if (!valid.has(bearer))
        return new Response("{}", {
          status: 401,
          headers: {
            "www-authenticate": `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"`,
          },
        });
      return handler.fetch(request);
    }
    if (url.host !== "auth.example.com")
      return Promise.reject(new TypeError("no route"));
    switch (url.pathname) {
      case "/.well-known/oauth-authorization-server":
        return json({
          issuer: "https://auth.example.com",
          authorization_endpoint: "https://auth.example.com/authorize",
          token_endpoint: "https://auth.example.com/token",
          registration_endpoint: "https://auth.example.com/register",
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
          authorization_response_iss_parameter_supported: true,
        });
      case "/register": {
        stats.registrations += 1;
        const body = Schema.decodeUnknownSync(
          Schema.Struct({
            redirect_uris: Schema.mutable(Schema.Array(Schema.String)),
          }),
        )(await request.json());
        const clientId = `dcr-${String(stats.registrations)}`;
        clients.set(clientId, {});
        return json({ ...body, client_id: clientId }, 201);
      }
      case "/token": {
        await gate;
        const form = new URLSearchParams(await request.text());
        const clientId = form.get("client_id") ?? "";
        const known = clients.get(clientId);
        const secret = form.get("client_secret");
        if (secret !== null) stats.tokenSecrets.push(secret);
        if (known === undefined || known.secret !== (secret ?? undefined))
          return json({ error: "invalid_client" }, 401);
        if (form.get("grant_type") === "authorization_code") {
          const code = codes.get(form.get("code") ?? "");
          codes.delete(form.get("code") ?? "");
          const verifier = form.get("code_verifier") ?? "";
          const challenge = createHash("sha256")
            .update(verifier)
            .digest("base64url");
          if (code?.challenge !== challenge || code.clientId !== clientId)
            return json({ error: "invalid_grant" }, 400);
          return json(mint(clientId));
        }
        const old = form.get("refresh_token") ?? "";
        if (refreshes.get(old) !== clientId)
          return json({ error: "invalid_grant" }, 400);
        refreshes.delete(old);
        stats.refreshes += 1;
        return json(mint(clientId));
      }
      default:
        return new Response("not found", { status: 404 });
    }
  };
  /** The owner's browser approving: the code lands on the callback with state and iss. */
  const approve = (authorizeUrl: string, iss = "https://auth.example.com") => {
    const query = new URL(authorizeUrl).searchParams;
    const code = `code-${String(codes.size + 1)}-${query.get("state") ?? ""}`;
    codes.set(code, {
      challenge: query.get("code_challenge") ?? "",
      clientId: query.get("client_id") ?? "",
    });
    return {
      state: query.get("state") ?? "",
      code,
      iss,
      redirect: query.get("redirect_uri"),
    };
  };
  return {
    fetch,
    approve,
    stats,
    clients,
    expireAccessTokens: () => {
      valid.clear();
    },
    forgetRefreshTokens: () => {
      refreshes.clear();
    },
    holdTokens: () => {
      let release = () => undefined;
      gate = new Promise<void>((resolve) => {
        release = () => {
          resolve();
        };
      });
      return () => {
        release();
        gate = undefined;
      };
    },
    shortLived: (seconds: number) => {
      tokenLife = seconds;
    },
  };
}

function harness(ownerId = "owner-1") {
  const remote = world();
  const database = new DatabaseSync(":memory:");
  const vault = new Map<string, string>();
  let counter = 0;
  let now = 1_000_000;
  const connections = createConnections({
    ownerId,
    store: fromNodeSqlite(database),
    custody: createSealedCustody({
      vault: {
        put: ({ secret }) => {
          counter += 1;
          const id = `cred-${String(counter)}`;
          vault.set(id, secret);
          return Promise.resolve({ credentialId: id });
        },
        withSecret: (id, action) => {
          const secret = vault.get(id);
          if (secret === undefined)
            return Promise.reject(
              Object.assign(new Error("absent"), { code: "absent" }),
            );
          return Promise.resolve(action(secret));
        },
        remove: (id) =>
          Promise.resolve(vault.delete(id) ? "deleted" : "absent"),
      },
      send: remote.fetch,
    }),
    authorize: (actor) => actor === "owner",
    oauth: { callbackUrl: callback, fetch: remote.fetch },
    clock: () => now,
    ids: () => `id${String((counter += 1))}`,
  });
  const run = <A>(effect: Effect.Effect<A, ConnectionsError>) =>
    Effect.runPromise(effect);
  const begin = (
    requestId: string,
    extra: { clientId?: string; secret?: string } = {},
  ) =>
    run(
      connections.begin("owner", {
        requestId,
        name: `Docs ${requestId}`,
        surface: { kind: "mcp", url: mcp },
        credential: { kind: "oauth", clientId: extra.clientId },
        secret: extra.secret,
      }),
    );
  const connect = async (requestId = "req-1") => {
    const started = await begin(requestId);
    const approval = remote.approve(started.authorizeUrl ?? "");
    await run(connections.complete("owner", approval));
    const { grantVersion } = await run(
      connections.grant("owner", {
        connectionId: started.connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    return { ...started, grantVersion, approval };
  };
  const tools = async (fetch: NarrowFetch) => {
    const client = new Client({ name: "test", version: "1" });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(mcp), {
        fetch,
        requestInit: { redirect: "error" },
      }),
    );
    try {
      return (await client.listTools()).tools.map((tool) => tool.name);
    } finally {
      await client.close();
    }
  };
  const dump = () =>
    JSON.stringify(
      [
        "veil_connections",
        "veil_connection_attempts",
        "veil_connection_receipts",
        "veil_oauth_clients",
      ].map((table) => database.prepare(`SELECT * FROM ${table}`).all()),
    );
  return {
    remote,
    database,
    vault,
    connections,
    run,
    begin,
    connect,
    tools,
    dump,
    advance: (ms: number) => {
      now += ms;
    },
  };
}
const code = (promise: Promise<unknown>) =>
  promise.then(
    () => "ok",
    (error: unknown) =>
      error instanceof ConnectionsError ? error.code : "other",
  );

describe("oauth connections", () => {
  it("discovers, registers, redirects with PKCE and lists tools after the callback", async () => {
    const h = harness();
    const started = await h.begin("req-1");
    const url = new URL(started.authorizeUrl ?? "");
    expect(url.origin + url.pathname).toBe(
      "https://auth.example.com/authorize",
    );
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("redirect_uri")).toBe(callback);
    expect(url.searchParams.get("state")?.startsWith("owner-1.")).toBe(true);
    expect(h.remote.stats.registrations).toBe(1);
    expect((await h.run(h.connections.list("owner")))[0]?.state).toBe(
      "pending",
    );
    // Nothing is usable until the callback settles the attempt.
    await h.run(
      h.connections.grant("owner", {
        connectionId: started.connectionId,
        agentId: "agent-a",
        tools: "all",
      }),
    );
    expect(
      (await h.run(h.connections.projection("agent-a"))).connections,
    ).toEqual([]);
    await h.run(
      h.connections.complete(
        "owner",
        h.remote.approve(started.authorizeUrl ?? ""),
      ),
    );
    const projection = await h.run(h.connections.projection("agent-a"));
    const ref = projection.connections[0];
    expect(ref?.surface.kind).toBe("mcp");
    const egress = h.connections.egress("agent-a", {
      connectionId: started.connectionId,
      grantVersion: ref?.grantVersion ?? 0,
    });
    expect(await h.tools(egress)).toEqual(["ping"]);
    for (const secret of ["access-1", "refresh-1"]) {
      expect(h.dump()).not.toContain(secret);
      expect(JSON.stringify(projection)).not.toContain(secret);
    }
    // A second connection to the same issuer reuses the registered client.
    await h.begin("req-2");
    expect(h.remote.stats.registrations).toBe(1);
  });

  it("refuses a replayed, expired, foreign or mis-issued state", async () => {
    const h = harness();
    const first = await h.begin("req-1");
    const approval = h.remote.approve(first.authorizeUrl ?? "");
    await h.run(h.connections.complete("owner", approval));
    expect(await code(h.run(h.connections.complete("owner", approval)))).toBe(
      "denied",
    );

    const stale = await h.begin("req-2");
    h.advance(11 * 60 * 1000);
    expect(
      await code(
        h.run(
          h.connections.complete(
            "owner",
            h.remote.approve(stale.authorizeUrl ?? ""),
          ),
        ),
      ),
    ).toBe("denied");
    const views = await h.run(h.connections.list("owner"));
    expect(
      views.find((view) => view.connectionId === stale.connectionId)?.state,
    ).toBe("revoked");

    const foreign = harness("owner-2");
    const mine = await h.begin("req-3");
    expect(
      await code(
        foreign.run(
          foreign.connections.complete(
            "owner",
            h.remote.approve(mine.authorizeUrl ?? ""),
          ),
        ),
      ),
    ).toBe("denied");
    expect(
      await code(
        h.run(
          h.connections.complete(
            "stranger",
            h.remote.approve(mine.authorizeUrl ?? ""),
          ),
        ),
      ),
    ).toBe("denied");

    const mixedUp = await h.begin("req-4");
    const wrong = h.remote.approve(
      mixedUp.authorizeUrl ?? "",
      "https://evil.example.net",
    );
    expect(await code(h.run(h.connections.complete("owner", wrong)))).not.toBe(
      "ok",
    );
    expect(
      (await h.run(h.connections.list("owner"))).find(
        (view) => view.connectionId === mixedUp.connectionId,
      )?.state,
    ).toBe("revoked");
  });

  it("refreshes exactly once across concurrent 401s and persists the rotated token", async () => {
    const h = harness();
    const connected = await h.connect();
    const egress = h.connections.egress("agent-a", {
      connectionId: connected.connectionId,
      grantVersion: connected.grantVersion,
    });
    const before = [...h.vault.keys()];
    h.remote.expireAccessTokens();
    const answers = await Promise.all(
      [1, 2, 3, 4, 5].map(() =>
        egress(
          new Request(mcp, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              accept: "application/json, text/event-stream",
            },
            body: JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              method: "tools/list",
            }),
            redirect: "error",
          }),
        ),
      ),
    );
    expect(answers.map((answer) => answer.status)).not.toContain(401);
    expect(h.remote.stats.refreshes).toBe(1);
    await h.run(h.connections.sweep());
    expect(h.vault.size).toBe(before.length);
    expect(
      [...h.vault.values()].some((value) => value.includes("refresh-2")),
    ).toBe(true);
    expect(await h.tools(egress)).toEqual(["ping"]);
    expect(h.remote.stats.refreshes).toBe(1);
  });

  it("refreshes before expiry and marks reconnect when the grant is gone", async () => {
    const h = harness();
    h.remote.shortLived(60);
    const connected = await h.connect();
    const egress = h.connections.egress("agent-a", {
      connectionId: connected.connectionId,
      grantVersion: connected.grantVersion,
    });
    h.advance(45_000);
    expect(await h.tools(egress)).toEqual(["ping"]);
    expect(h.remote.stats.refreshes).toBe(1);
    // The server forgets every refresh token: only a new authorization helps.
    h.remote.expireAccessTokens();
    h.remote.forgetRefreshTokens();
    h.advance(120_000);
    expect(await code(h.tools(egress))).not.toBe("ok");
    expect((await h.run(h.connections.list("owner")))[0]?.state).toBe(
      "reconnect_required",
    );
  });

  it("does not reactivate a connection revoked during a refresh", async () => {
    const h = harness();
    const connected = await h.connect();
    const egress = h.connections.egress("agent-a", {
      connectionId: connected.connectionId,
      grantVersion: connected.grantVersion,
    });
    h.remote.expireAccessTokens();
    const release = h.remote.holdTokens();
    const pending = code(h.tools(egress));
    await new Promise((resolve) => setTimeout(resolve, 50));
    await h.run(
      h.connections.revoke("owner", { connectionId: connected.connectionId }),
    );
    release();
    expect(await pending).not.toBe("ok");
    await h.run(h.connections.sweep());
    expect((await h.run(h.connections.list("owner")))[0]?.state).toBe(
      "revoked",
    );
    expect(h.vault.size).toBe(1); // only the shared issuer client remains
    expect(await code(h.tools(egress))).not.toBe("ok");
  });

  it("does not activate a connection revoked while its code is redeemed", async () => {
    const h = harness();
    const started = await h.begin("req-1");
    const approval = h.remote.approve(started.authorizeUrl ?? "");
    const release = h.remote.holdTokens();
    const pending = code(h.run(h.connections.complete("owner", approval)));
    await new Promise((resolve) => setTimeout(resolve, 50));
    await h.run(
      h.connections.revoke("owner", { connectionId: started.connectionId }),
    );
    release();
    expect(await pending).toBe("revoked");
    await h.run(h.connections.sweep());
    expect((await h.run(h.connections.list("owner")))[0]?.state).toBe(
      "revoked",
    );
    expect(h.vault.size).toBe(1); // only the shared issuer client remains
  });

  it("uses an owner-supplied client and seals its secret", async () => {
    const h = harness();
    h.remote.clients.set("owner-app", { secret: clientSecret });
    const started = await h.begin("req-1", {
      clientId: "owner-app",
      secret: clientSecret,
    });
    expect(h.remote.stats.registrations).toBe(0);
    await h.run(
      h.connections.complete(
        "owner",
        h.remote.approve(started.authorizeUrl ?? ""),
      ),
    );
    expect(h.remote.stats.tokenSecrets).toEqual([clientSecret]);
    expect(h.dump()).not.toContain(clientSecret);
    await expect(
      h.run(
        h.connections.begin("owner", {
          requestId: "r",
          name: "x",
          surface: { kind: "mcp", url: mcp },
          credential: { kind: "oauth" },
          secret: clientSecret,
        }),
      ),
    ).rejects.toMatchObject({ code: "invalid_input" });
  });
});
