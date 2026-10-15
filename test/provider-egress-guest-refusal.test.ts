import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { VeilError } from "../src/index.js";
import {
  createProviderEgress,
  providerFetch,
  type ProviderKeyBindings,
  type ProviderRoute,
} from "../src/provider-egress.js";

// V1b acceptance: "guest cannot read any credential value" for the platform
// provider keys. A guest or codemode principal is anyone who can call the
// egress door without owning a key. Every refusal below must stop the call
// before the key leaves Veil, and no observable surface (thrown error, returned
// value, response headers, anything logged) may carry a key value.

const CAMEL = "synthetic-camel-key-do-not-leak";
const GATEWAY = "synthetic-gateway-token-do-not-leak";
const PARALLEL = "synthetic-parallel-key-do-not-leak";
const SECRETS = [CAMEL, GATEWAY, PARALLEL];

const env: ProviderKeyBindings = {
  CAMEL_API_KEY: CAMEL,
  AI_GATEWAY_AUTH_TOKEN: GATEWAY,
  PARALLEL_API_KEY: PARALLEL,
  AI_GATEWAY_ACCOUNT_ID: "acct1",
  AI_GATEWAY_ID: "gw1",
};

const GATEWAY_COMPAT =
  "https://gateway.ai.cloudflare.com/v1/acct1/gw1/compat/chat/completions";
const GATEWAY_LOGS =
  "https://api.cloudflare.com/client/v4/accounts/acct1/ai-gateway/gateways/gw1/logs?page=1";

let logs: string[] = [];
beforeEach(() => {
  logs = [];
  const capture = (...args: unknown[]) => {
    logs.push(args.map((arg) => String(arg)).join(" "));
  };
  for (const method of ["log", "info", "warn", "error", "debug"] as const)
    vi.spyOn(console, method).mockImplementation(capture);
});
afterEach(() => {
  vi.restoreAllMocks();
});

function assertNoSecretLeak(surfaces: readonly string[]) {
  for (const surface of [...surfaces, ...logs])
    for (const secret of SECRETS) expect(surface.includes(secret)).toBe(false);
}

/** An upstream that records what it was sent and echoes nothing secret. */
function upstream() {
  const seen: Request[] = [];
  const spy = vi.fn((request: Request) => {
    seen.push(request);
    return Promise.resolve(Response.json({ ok: true }));
  });
  const fetch: typeof globalThis.fetch = (input, init) =>
    spy(new Request(input, init));
  return { seen, fetch, spy };
}

async function refusal(attempt: Promise<Response>): Promise<VeilError> {
  try {
    await attempt;
  } catch (error) {
    if (error instanceof VeilError) return error;
    throw error;
  }
  throw new Error("expected the attempt to be refused");
}

const routes: readonly (readonly [ProviderRoute, string])[] = [
  ["camel", "https://stream.camelai.com/v1/responses"],
  ["ai-gateway", GATEWAY_COMPAT],
  [
    "parallel",
    "https://gateway.ai.cloudflare.com/v1/acct1/gw1/parallel/v1/search",
  ],
  ["ai-gateway-logs", GATEWAY_LOGS],
];

it("attaches exactly the route's own credential and drops any a guest supplies", async () => {
  for (const [route, url] of routes) {
    const { seen, fetch } = upstream();
    const egress = createProviderEgress(env, { fetch });
    const response = await egress.fetch(route, url, {
      method: "POST",
      headers: {
        authorization: "Bearer guest-supplied",
        "x-api-key": "guest-supplied",
        "cf-aig-authorization": "Bearer guest-supplied",
        "proxy-authorization": "guest-supplied",
        "cf-aig-metadata": "keep-me",
      },
      body: "{}",
    });
    expect(response.status, route).toBe(200);
    const sent = seen[0];
    expect(sent, route).toBeDefined();
    const headers = sent?.headers;
    headers?.forEach((value) => {
      expect(value.includes("guest-supplied"), route).toBe(false);
    });
    expect(headers?.get("proxy-authorization"), route).toBeNull();
    expect(headers?.get("cf-aig-metadata"), route).toBe("keep-me");
    expect(sent?.redirect, route).toBe("manual");
    assertNoSecretLeak([
      JSON.stringify([...response.headers.entries()]),
      await response.text(),
    ]);
  }
  const camel = upstream();
  await createProviderEgress(env, { fetch: camel.fetch }).fetch(
    "camel",
    routes[0]?.[1] ?? "",
  );
  expect(camel.seen[0]?.headers.get("authorization")).toBe(`Bearer ${CAMEL}`);
  const gateway = upstream();
  await createProviderEgress(env, { fetch: gateway.fetch }).fetch(
    "ai-gateway",
    GATEWAY_COMPAT,
  );
  expect(gateway.seen[0]?.headers.get("authorization")).toBeNull();
  expect(gateway.seen[0]?.headers.get("cf-aig-authorization")).toBe(
    `Bearer ${GATEWAY}`,
  );
  const search = upstream();
  await createProviderEgress(env, { fetch: search.fetch }).fetch(
    "parallel",
    routes[2]?.[1] ?? "",
  );
  expect(search.seen[0]?.headers.get("x-api-key")).toBe(PARALLEL);
  expect(search.seen[0]?.headers.get("cf-aig-authorization")).toBeNull();
});

it("refuses a destination outside the route before the key leaves Veil", async () => {
  const wrong: readonly (readonly [ProviderRoute, string])[] = [
    ["camel", "https://evil.example/v1/responses"],
    ["camel", "http://stream.camelai.com/v1/responses"],
    ["camel", "https://stream.camelai.com@evil.example/v1/responses"],
    ["camel", "https://stream.camelai.com/v2/responses"],
    ["camel", "https://stream.camelai.com/v1evil/responses"],
    ["camel", "https://stream.camelai.com.evil.example/v1/responses"],
    ["ai-gateway", "https://gateway.ai.cloudflare.com/v1/acct1/gw1/parallel/x"],
    ["ai-gateway", "https://gateway.ai.cloudflare.com/v1/other/gw1/compat/x"],
    [
      "ai-gateway",
      "https://gateway.ai.cloudflare.com/v1/acct1/gw1/compat/../../gw2/compat/x",
    ],
    [
      "ai-gateway",
      "https://gateway.ai.cloudflare.com/v1/acct1/gw1/compat-evil/x",
    ],
    ["parallel", "https://api.parallel.ai/v1/search"],
    ["parallel", "https://evil.example/v1/search"],
    ["ai-gateway-logs", "https://api.cloudflare.com/client/v4/user/tokens"],
    [
      "ai-gateway-logs",
      "https://api.cloudflare.com/client/v4/accounts/acct1/ai-gateway/gateways/gw2/logs",
    ],
  ];
  for (const [route, url] of wrong) {
    const { fetch, spy } = upstream();
    const egress = createProviderEgress(env, { fetch });
    const error = await refusal(egress.fetch(route, url));
    expect(error.code, `${route} ${url}`).toBe("denied");
    expect(spy, `${route} ${url}`).not.toHaveBeenCalled();
    assertNoSecretLeak([String(error), JSON.stringify({ code: error.code })]);
  }
});

it("a route with no credential is unavailable and sends nothing", async () => {
  for (const [route, url] of routes) {
    const { fetch, spy } = upstream();
    const egress = createProviderEgress({}, { fetch });
    expect(egress.credentialed(route)).toBe(false);
    expect(egress.baseUrl(route)).toBeNull();
    const error = await refusal(egress.fetch(route, url));
    expect(error.code, route).toBe("unavailable");
    expect(spy, route).not.toHaveBeenCalled();
  }
  // A gateway route also needs the gateway named, not just its token.
  const { fetch, spy } = upstream();
  const unnamed = createProviderEgress(
    { AI_GATEWAY_AUTH_TOKEN: GATEWAY },
    { fetch },
  );
  expect(unnamed.credentialed("ai-gateway")).toBe(true);
  expect(unnamed.baseUrl("ai-gateway")).toBeNull();
  const error = await refusal(unnamed.fetch("ai-gateway", GATEWAY_COMPAT));
  expect(error.code).toBe("unavailable");
  expect(spy).not.toHaveBeenCalled();
});

it("parallel falls back to Parallel direct only when no gateway is named", async () => {
  const { seen, fetch } = upstream();
  const direct = createProviderEgress(
    { PARALLEL_API_KEY: PARALLEL },
    { fetch },
  );
  expect(direct.baseUrl("parallel")).toBe("https://api.parallel.ai");
  await direct.fetch("parallel", "https://api.parallel.ai/v1/search");
  expect(seen[0]?.headers.get("x-api-key")).toBe(PARALLEL);
});

it("reveals no credential value through its own surface", () => {
  const egress = createProviderEgress(env, { fetch: upstream().fetch });
  const surfaces: string[] = [
    JSON.stringify(egress),
    Object.keys(egress).join(","),
  ];
  for (const [route] of routes) {
    surfaces.push(
      String(egress.credentialed(route)),
      String(egress.baseUrl(route)),
    );
  }
  assertNoSecretLeak(surfaces);
});

it("sanitizes a transport failure, but keeps a caller's own cancellation", async () => {
  const failing: typeof globalThis.fetch = () =>
    Promise.reject(new Error(`boom ${CAMEL} ${GATEWAY} ${PARALLEL}`));
  const egress = createProviderEgress(env, { fetch: failing });
  const error = await refusal(egress.fetch("camel", routes[0]?.[1] ?? ""));
  expect(error.code).toBe("unavailable");
  assertNoSecretLeak([String(error), error.message, JSON.stringify(error)]);

  const controller = new AbortController();
  const cancelled: typeof globalThis.fetch = () => {
    controller.abort(new Error("caller cancelled"));
    return Promise.reject(new Error("aborted"));
  };
  await expect(
    createProviderEgress(env, { fetch: cancelled }).fetch(
      "camel",
      routes[0]?.[1] ?? "",
      { signal: controller.signal },
    ),
  ).rejects.toThrow("aborted");
});

it("a route-bound fetch carries the same refusals", async () => {
  const { fetch, spy } = upstream();
  const bound = providerFetch(createProviderEgress(env, { fetch }), "camel");
  await expect(
    bound("https://evil.example/v1/responses"),
  ).rejects.toMatchObject({ code: "denied" });
  expect(spy).not.toHaveBeenCalled();
  expect((await bound(routes[0]?.[1] ?? "")).status).toBe(200);
});
