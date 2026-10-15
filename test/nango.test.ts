import { createHmac } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { createNangoCustodian } from "../src/nango.js";
import {
  createGitHubConnections,
  VeilError,
  type TeamConnectionsOwner,
} from "../src/index.js";

const options = {
  serverUrl: "https://custodian.example",
  apiKey: "synthetic-api-key",
  webhookSigningKey: "synthetic-signing-key",
  integrationId: "github-private",
  connectBaseUrl: "https://connect.example/ui",
  publicApiUrl: "https://connect.example",
};
const attempt = {
  teamId: "team-a",
  attemptId: "attempt-a",
  actorUserId: "user-a",
  holderAgentId: "agent-a",
  connectionId: "connection-a",
  integrationId: options.integrationId,
  requestId: "request-a",
  expiresAt: 2000000000000,
  repository: { id: 42, owner: "botanical", name: "bound" },
};
const tags = {
  veil_team_id: attempt.teamId,
  veil_attempt_id: attempt.attemptId,
  veil_principal_id: attempt.actorUserId,
};
const row = {
  connection_id: "private-locator",
  provider_config_key: options.integrationId,
  tags,
  end_user: { id: attempt.actorUserId, organization: { id: attempt.teamId } },
};
const webhook = {
  type: "auth",
  operation: "creation",
  success: true,
  connectionId: row.connection_id,
  providerConfigKey: options.integrationId,
  tags,
  endUser: { endUserId: attempt.actorUserId, organizationId: attempt.teamId },
};
const signature = (body: string, key = options.webhookSigningKey) =>
  createHmac("sha256", key).update(body).digest("hex");
const signal = () => new AbortController().signal;
afterEach(() => vi.unstubAllGlobals());

it("uses maintained raw-body verification and checks signed principal correlation", async () => {
  const adapter = createNangoCustodian(options);
  const raw = JSON.stringify(webhook);
  await expect(adapter.verifyCompletion(raw, signature(raw))).resolves.toEqual({
    teamId: attempt.teamId,
    attemptId: attempt.attemptId,
    principalId: attempt.actorUserId,
    integrationId: options.integrationId,
    locator: row.connection_id,
  });
  const invalidSignatures: [string, string][] = [
    [raw + " ", signature(raw)],
    [raw, signature(raw, options.apiKey)],
    [raw, ""],
  ];
  for (const [body, signed] of invalidSignatures)
    await expect(adapter.verifyCompletion(body, signed)).rejects.toMatchObject({
      code: "invalid_completion",
    });
  const wrong = JSON.stringify({
    ...webhook,
    endUser: { ...webhook.endUser, endUserId: "other" },
  });
  await expect(
    adapter.verifyCompletion(wrong, signature(wrong)),
  ).rejects.toMatchObject({ code: "invalid_completion" });
});

it("sends only trusted Connect scope and decodes temporary ceremony output", async () => {
  const transport = vi.fn<typeof fetch>(async (_url, init) => {
    expect(await new Request(_url, init).json()).toEqual({
      allowed_integrations: [options.integrationId],
      end_user: { id: attempt.actorUserId },
      organization: { id: attempt.teamId },
      tags,
    });
    expect(new Headers(init?.headers).get("Authorization")).toBe(
      `Bearer ${options.apiKey}`,
    );
    expect(init?.redirect).toBe("manual");
    return Response.json({
      data: {
        token: "temporary-token",
        connect_link:
          "https://connect.example/ui/?session_token=temporary-token",
        expires_at: "2030-01-01T00:00:00.000Z",
      },
    });
  });
  vi.stubGlobal("fetch", transport);
  await expect(
    createNangoCustodian(options).openSession(
      {
        teamId: attempt.teamId,
        attemptId: attempt.attemptId,
        principalId: attempt.actorUserId,
        integrationId: attempt.integrationId,
      },
      signal(),
    ),
  ).resolves.toEqual({
    token: "temporary-token",
    // The one Hub path pins the browser's Connect UI to the public API.
    connectUrl:
      "https://connect.example/ui/?session_token=temporary-token&apiURL=https%3A%2F%2Fconnect.example%2F",
    expiresAt: 1893456000000,
  });
  expect(transport).toHaveBeenCalledTimes(1);
});

it.each([301, 302, 303, 307, 308])(
  "rejects Connect redirect %i without forwarding custody to its target",
  async (status) => {
    const transport = vi.fn<typeof fetch>((_url, init) => {
      expect(init?.redirect).toBe("manual");
      return Promise.resolve(
        new Response(null, {
          status,
          headers: { Location: "https://other.example/collect" },
        }),
      );
    });
    vi.stubGlobal("fetch", transport);
    await expect(
      createNangoCustodian(options).openSession(
        {
          teamId: attempt.teamId,
          attemptId: attempt.attemptId,
          principalId: attempt.actorUserId,
          integrationId: attempt.integrationId,
        },
        signal(),
      ),
    ).rejects.toMatchObject({ code: "unavailable" });
    expect(transport).toHaveBeenCalledTimes(1);
  },
);

it.each([0, 1, 2])(
  "reconciles %i exact filtered matches without taking the first ambiguous row",
  async (count) => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const url = new URL(new Request(input).url);
        expect(url.pathname).toBe("/connections");
        expect(url.searchParams.get("limit")).toBe("2");
        expect(url.searchParams.get("tags[veil_attempt_id]")).toBe(
          attempt.attemptId,
        );
        expect(url.searchParams.get("endUserOrganizationId")).toBe(
          attempt.teamId,
        );
        return Promise.resolve(
          Response.json({
            connections: Array.from({ length: count }, (_, i) => ({
              ...row,
              connection_id: `locator-${String(i)}`,
            })),
          }),
        );
      }),
    );
    const result = await createNangoCustodian(options).findCompletion(
      {
        teamId: attempt.teamId,
        attemptId: attempt.attemptId,
        actorUserId: attempt.actorUserId,
        integrationId: attempt.integrationId,
      },
      signal(),
    );
    expect(result.status).toBe(
      count === 0 ? "unresolved" : count === 1 ? "verified" : "ambiguous",
    );
  },
);

it("does not trust list filters instead of checking returned correlation", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn<typeof fetch>(() =>
      Promise.resolve(
        Response.json({
          connections: [{ ...row, tags: { ...tags, veil_team_id: "other" } }],
        }),
      ),
    ),
  );
  await expect(
    createNangoCustodian(options).findCompletion(attempt, signal()),
  ).rejects.toMatchObject({ code: "invalid_response" });
});

it.each([
  { status: 200, body: { success: true }, result: "deleted" },
  {
    status: 400,
    body: { error: { code: "unknown_connection" } },
    result: "absent",
  },
  {
    status: 404,
    body: { error: { code: "unknown_connection" } },
    result: "unavailable",
  },
  { status: 200, body: { success: false }, result: "invalid_response" },
  { status: 500, body: { secret: "vendor-private" }, result: "unavailable" },
])(
  "deletion distinguishes $status / $result",
  async ({ status, body, result }) => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(Response.json(body, { status })),
      ),
    );
    const pending = createNangoCustodian(options).deleteConnection(
      "private-locator",
      signal(),
    );
    if (result === "deleted" || result === "absent")
      await expect(pending).resolves.toBe(result);
    else
      await expect(pending).rejects.toMatchObject({
        code: result,
        message: result,
      });
  },
);

it("same metadata caller checks fresh Team authority before Nango egress and strips provider extras", async () => {
  let allowed = true;
  const unused = () => {
    throw new Error("Unexpected lifecycle call");
  };
  const owner: TeamConnectionsOwner = {
    begin: unused,
    readAttempt: unused,
    prepareCompletion: unused,
    recordOrphan: unused,
    requireReconnect: unused,
    activate: unused,
    disconnect: unused,
    nextCleanup: unused,
    acknowledgeCleanup: unused,
    authorize: () => {
      if (!allowed) throw new VeilError("denied");
      return { locator: row.connection_id, repository: attempt.repository };
    },
  };
  const transport = vi.fn<typeof fetch>((input, init) => {
    expect(new Request(input).url).toBe(
      "https://custodian.example/proxy/repos/botanical/bound",
    );
    expect(new Headers(init?.headers).get("Connection-Id")).toBe(
      row.connection_id,
    );
    return Promise.resolve(
      Response.json({
        id: 42,
        name: "bound",
        full_name: "botanical/bound",
        private: true,
        default_branch: "main",
        credentials: "must-not-escape",
      }),
    );
  });
  vi.stubGlobal("fetch", transport);
  const caller = createGitHubConnections({
    owner,
    custodian: createNangoCustodian(options),
  });
  const binding = {
    teamId: attempt.teamId,
    holderAgentId: attempt.holderAgentId,
    connectionId: attempt.connectionId,
    repositoryId: 42,
  };
  await expect(caller.readRepository(binding)).resolves.toEqual({
    id: 42,
    name: "bound",
    fullName: "botanical/bound",
    private: true,
    defaultBranch: "main",
  });
  allowed = false;
  await expect(caller.readRepository(binding)).rejects.toMatchObject({
    code: "denied",
  });
  expect(transport).toHaveBeenCalledTimes(1);
});

it("does not acquire transport after cancellation and sanitizes transport rejection", async () => {
  const transport = vi.fn<typeof fetch>(() =>
    Promise.reject(new Error("secret-vendor-detail")),
  );
  vi.stubGlobal("fetch", transport);
  const adapter = createNangoCustodian(options);
  const controller = new AbortController();
  controller.abort();
  const access = { locator: row.connection_id, repository: attempt.repository };
  await expect(
    adapter.readRepository(access, controller.signal),
  ).rejects.toMatchObject({ code: "cancelled", message: "cancelled" });
  expect(transport).not.toHaveBeenCalled();
  await expect(adapter.readRepository(access, signal())).rejects.toMatchObject({
    code: "unavailable",
    message: "unavailable",
  });
});

it("carries the invocation signal into an in-flight request and sanitizes its abort reason", async () => {
  let entered: (() => void) | undefined;
  const ready = new Promise<void>((resolve) => {
    entered = resolve;
  });
  vi.stubGlobal(
    "fetch",
    vi.fn<typeof fetch>(async (_input, init) => {
      entered?.();
      return await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => {
            reject(new Error("private abort detail"));
          },
          { once: true },
        );
      });
    }),
  );
  const controller = new AbortController();
  const pending = createNangoCustodian(options).readRepository(
    { locator: row.connection_id, repository: attempt.repository },
    controller.signal,
  );
  const rejected = expect(pending).rejects.toMatchObject({
    code: "cancelled",
    message: "cancelled",
  });
  await ready;
  controller.abort();
  await rejected;
});

it("bounds a custodian that never answers as retryable unavailable, never invalidity", async () => {
  const transport = vi.fn<typeof fetch>(
    async (_input, init) =>
      await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => {
            reject(new Error("private hang detail"));
          },
          { once: true },
        );
      }),
  );
  vi.stubGlobal("fetch", transport);
  const adapter = createNangoCustodian({ ...options, requestTimeoutMs: 50 });
  const started = Date.now();
  await expect(
    adapter.readRepository(
      { locator: row.connection_id, repository: attempt.repository },
      signal(),
    ),
  ).rejects.toMatchObject({ code: "unavailable", message: "unavailable" });
  await expect(
    adapter.openSession(
      {
        teamId: attempt.teamId,
        attemptId: attempt.attemptId,
        principalId: attempt.actorUserId,
        integrationId: options.integrationId,
      },
      signal(),
    ),
  ).rejects.toMatchObject({ code: "unavailable" });
  expect(Date.now() - started).toBeLessThan(5_000);
  expect(transport).toHaveBeenCalledTimes(2);
});

it("rejects URL-normalized repository dot segments before egress", async () => {
  const transport = vi.fn<typeof fetch>();
  vi.stubGlobal("fetch", transport);
  await expect(
    createNangoCustodian(options).readRepository(
      {
        locator: row.connection_id,
        repository: { ...attempt.repository, owner: ".." },
      },
      signal(),
    ),
  ).rejects.toMatchObject({ code: "invalid_input" });
  expect(transport).not.toHaveBeenCalled();
});

it("verifies a signed refresh failure as reconnect evidence and refuses unhandled operations", async () => {
  const adapter = createNangoCustodian(options);
  const refresh = JSON.stringify({
    ...webhook,
    operation: "refresh",
    success: false,
    error: { type: "refresh_token_external_error", description: "private" },
  });
  await expect(
    adapter.verifyWebhook(refresh, signature(refresh)),
  ).resolves.toEqual({
    operation: "refresh_failed",
    completion: {
      teamId: attempt.teamId,
      attemptId: attempt.attemptId,
      principalId: attempt.actorUserId,
      integrationId: options.integrationId,
      locator: row.connection_id,
    },
  });
  // Activation accepts connection creation only.
  await expect(
    adapter.verifyCompletion(refresh, signature(refresh)),
  ).rejects.toMatchObject({ code: "unsupported" });
  await expect(
    adapter.verifyWebhook(refresh, signature(refresh, options.apiKey)),
  ).rejects.toMatchObject({ code: "invalid_completion" });
  for (const changes of [
    { operation: "override" },
    { operation: "deletion" },
    { operation: "unknown" },
    { operation: "synthetic-future-operation" },
    { operation: undefined },
    { operation: "creation", success: false },
    { operation: "refresh", success: true },
    { type: "sync" },
  ]) {
    const raw = JSON.stringify({ ...webhook, ...changes });
    await expect(
      adapter.verifyWebhook(raw, signature(raw)),
    ).rejects.toMatchObject({ code: "unsupported" });
  }
});

it.each([
  {
    body: { message: "Bad credentials", documentation_url: "https://docs" },
    code: "reconnect_required",
  },
  {
    body: { error: { code: "unknown_account", message: "private" } },
    code: "unavailable",
  },
])(
  "maps a proxied 401 to $code and marks only provider evidence",
  async ({ body, code }) => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(Response.json(body, { status: 401 })),
      ),
    );
    const unused = () => {
      throw new Error("Unexpected lifecycle call");
    };
    const marked: unknown[] = [];
    const owner: TeamConnectionsOwner = {
      begin: unused,
      readAttempt: unused,
      prepareCompletion: unused,
      recordOrphan: unused,
      activate: unused,
      disconnect: unused,
      nextCleanup: unused,
      acknowledgeCleanup: unused,
      authorize: () => ({
        locator: row.connection_id,
        repository: attempt.repository,
      }),
      requireReconnect: (locator, reason) => {
        marked.push([locator, reason]);
        return {
          status: "reconnect_required",
          connectionId: attempt.connectionId,
        };
      },
    };
    await expect(
      createGitHubConnections({
        owner,
        custodian: createNangoCustodian(options),
      }).readRepository({
        teamId: attempt.teamId,
        holderAgentId: attempt.holderAgentId,
        connectionId: attempt.connectionId,
        repositoryId: 42,
      }),
    ).rejects.toMatchObject({ code });
    expect(marked).toEqual(
      code === "reconnect_required"
        ? [[row.connection_id, "provider_unauthorized"]]
        : [],
    );
  },
);
