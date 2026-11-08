import { expect, it, vi } from "vitest";
import { z } from "zod";
import { VeilError } from "../src/index.js";
import {
  configuredProviderEgress,
  type KeyedRoute,
} from "../src/gatekeeper.js";
import {
  createProviderEgress,
  providerFetch,
  type ProviderKeyBindings,
} from "../src/provider-egress.js";

// Host-registered keyed routes: the host names bindings, a pinned root and a
// body decoder; Veil reads the values, pins the destination and attaches the
// key. These synthetic routes stand in for any host's provider.

const PRIMARY = "synthetic-query-secret";
const FALLBACK = "synthetic-path-secret";
const QUERY_ROOT = "https://rpc.example.test/";
const PATH_ROOT = "https://alpha.path-rpc.example.test/";
const OFAC =
  "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML";

const call = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: z.union([z.string(), z.number()]),
    method: z.enum(["read", "count"]),
    params: z.array(z.unknown()).optional(),
  })
  .strict();

const keyed = {
  "query-rpc": {
    urlBinding: "QUERY_RPC_URL",
    keyBinding: "QUERY_RPC_KEY",
    accepts: (root) => root.href === QUERY_ROOT,
    credential: { in: "query", name: "api-key" },
    body: call,
  },
  "path-rpc": {
    urlBinding: "PATH_RPC_URL",
    keyBinding: "PATH_RPC_KEY",
    accepts: (root) =>
      /^[a-z0-9-]+\.path-rpc\.example\.test$/u.test(root.hostname),
    credential: { in: "path" },
    body: call,
  },
} satisfies Record<string, KeyedRoute>;
type Keyed = keyof typeof keyed;

const env = {
  QUERY_RPC_URL: QUERY_ROOT,
  QUERY_RPC_KEY: PRIMARY,
  PATH_RPC_URL: PATH_ROOT,
  PATH_RPC_KEY: FALLBACK,
  SANCTIONS_SDN_URL: OFAC,
};
type Env = ProviderKeyBindings & Readonly<Record<string, string>>;
function withoutBinding(name: string): Env {
  return Object.fromEntries(
    Object.entries(env).filter(([key]) => key !== name),
  );
}
const rpcRoutes = [
  ["query-rpc", QUERY_ROOT, PRIMARY],
  ["path-rpc", PATH_ROOT, FALLBACK],
] as const;
const request = (method = "read") => ({
  method: "POST",
  body: JSON.stringify({ jsonrpc: "2.0", id: "call-1", method, params: [] }),
  headers: { "content-type": "application/json" },
});

function upstream(
  response: () => Response = () => Response.json({ result: 42 }),
) {
  const seen: Request[] = [];
  const fetch: typeof globalThis.fetch = (input, init) => {
    seen.push(new Request(input, init));
    return Promise.resolve(response());
  };
  return { seen, fetch: vi.fn(fetch) };
}

async function denied(
  route: Keyed,
  url: string,
  init?: RequestInit,
  bindings: Env = env,
  code = "denied",
) {
  const { fetch, seen } = upstream();
  await expect(
    createProviderEgress(bindings, { fetch, keyed }).fetch(route, url, init),
  ).rejects.toMatchObject({ name: "VeilError", code });
  expect(seen).toHaveLength(0);
}

it("pins each keyed root and attaches its key only inside Veil", async () => {
  for (const [route, url, secret] of rpcRoutes) {
    const { fetch, seen } = upstream();
    const egress = configuredProviderEgress(env, { fetch, keyed });
    expect(egress.credentialed(route)).toBe(true);
    expect(egress.baseUrl(route)).toBe(url.replace(/\/$/u, ""));
    const bound = providerFetch(egress, route);
    for (const method of ["read", "count"]) {
      const response = await bound(url, {
        ...request(method),
        headers: {
          authorization: "Bearer caller",
          "x-api-key": "caller",
          "cf-aig-authorization": "caller",
          "proxy-authorization": "caller",
          cookie: "caller",
        },
      });
      expect(await response.json()).toEqual({ result: 42 });
    }
    for (const sent of seen) {
      const destination = new URL(sent.url);
      expect(destination.origin).toBe(new URL(url).origin);
      if (route === "query-rpc") {
        expect(destination.pathname).toBe("/");
        expect(destination.searchParams.get("api-key")).toBe(secret);
      } else {
        expect(destination.pathname).toBe(`/${secret}/`);
        expect(destination.search).toBe("");
      }
      expect([...sent.headers.keys()].sort()).toEqual([
        "accept",
        "content-type",
      ]);
      expect(sent.redirect).toBe("manual");
    }
    expect(JSON.stringify(egress)).not.toContain(secret);
    expect(egress.baseUrl(route)).not.toContain(secret);
  }
});

it("refuses every other origin, path, query, port and HTTP method before fetch", async () => {
  for (const [route, url] of rpcRoutes) {
    const base = new URL(url);
    for (const wrong of [
      "https://evil.example/",
      url.replace("https:", "http:"),
      url.replace(base.hostname, `${base.hostname}.evil.example`),
      url.replace(base.hostname, `${base.hostname}:444`),
      `${url}other`,
      `${url}?api-key=caller`,
      `${url}?other=1`,
      url.replace("https://", "https://caller:password@"),
    ])
      await denied(route, wrong, request());
    for (const method of ["GET", "PUT", "DELETE", "HEAD"])
      await denied(route, url, { method });
  }
  // Another root the host would accept is not this environment's pinned one.
  await denied("path-rpc", PATH_ROOT.replace("alpha.", "beta."), request());
});

it("refuses any body the host's decoder rejects, and malformed JSON", async () => {
  for (const [route, url] of rpcRoutes) {
    await denied(route, url, request("write"));
    for (const body of [
      JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "read" }]),
      JSON.stringify({ jsonrpc: "1.0", id: 1, method: "read" }),
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "read", extra: true }),
    ])
      await denied(route, url, { method: "POST", body });
    await denied(route, url, { method: "POST", body: "{" });
  }
});

it("missing, invalid or unaccepted configuration refuses without contacting any provider", async () => {
  for (const [route, url] of rpcRoutes) {
    await denied(route, url, request(), {}, "unavailable");
    const egress = createProviderEgress({}, { keyed });
    expect(egress.credentialed(route)).toBe(false);
    expect(egress.baseUrl(route)).toBeNull();
  }
  for (const bindings of [
    withoutBinding("QUERY_RPC_KEY"),
    withoutBinding("QUERY_RPC_URL"),
    { ...env, QUERY_RPC_URL: "invalid url" },
    { ...env, QUERY_RPC_URL: `${QUERY_ROOT}?api-key=${PRIMARY}` },
    { ...env, QUERY_RPC_URL: "https://other.example.test/" },
  ])
    await denied("query-rpc", QUERY_ROOT, request(), bindings, "unavailable");
  for (const bindings of [
    withoutBinding("PATH_RPC_KEY"),
    withoutBinding("PATH_RPC_URL"),
    { ...env, PATH_RPC_URL: `${PATH_ROOT}${FALLBACK}/` },
    { ...env, PATH_RPC_URL: "https://evil.example/" },
    { ...env, PATH_RPC_URL: "http://alpha.path-rpc.example.test/" },
  ])
    await denied("path-rpc", PATH_ROOT, request(), bindings, "unavailable");
});

it("refuses a host route that shadows a Veil route or borrows a Veil custody root", () => {
  const route = keyed["query-rpc"];
  const shadowing: readonly Record<string, KeyedRoute>[] = [
    { camel: route },
    { mine: { ...route, keyBinding: "CAMEL_API_KEY" } },
    { mine: { ...route, keyBinding: "NANGO_API_KEY" } },
    { mine: { ...route, urlBinding: "AI_GATEWAY_ID" } },
    { mine: { ...route, keyBinding: route.urlBinding } },
  ];
  for (const routes of shadowing)
    expect(() => createProviderEgress(env, { keyed: routes })).toThrow(
      VeilError,
    );
});

it("never returns transport errors, credential echoes, upstream URLs or headers, even on abort", async () => {
  for (const [route, url, secret] of rpcRoutes) {
    for (const status of [200, 302, 401, 500]) {
      const { fetch } = upstream(
        () =>
          new Response(secret, {
            status,
            headers: { location: `${url}${secret}`, "x-debug-key": secret },
          }),
      );
      await expect(
        createProviderEgress(env, { fetch, keyed }).fetch(
          route,
          url,
          request(),
        ),
      ).rejects.toMatchObject({ code: "unavailable", message: "unavailable" });
    }
    const controller = new AbortController();
    const fetch: typeof globalThis.fetch = () => {
      controller.abort();
      return Promise.reject(new Error(`upstream failed: ${url}${secret}`));
    };
    const egress = createProviderEgress(env, { fetch, keyed });
    const error: unknown = await egress
      .fetch(route, url, { ...request(), signal: controller.signal })
      .catch((cause: unknown) => cause);
    expect(error).toBeInstanceOf(VeilError);
    expect(JSON.stringify(error)).not.toContain(secret);
    expect(String(error)).not.toContain(secret);
    const clean = upstream(
      () =>
        new Response('{"result":42}', {
          headers: { "x-debug-key": secret, location: `${url}${secret}` },
        }),
    );
    const response = await createProviderEgress(env, {
      fetch: clean.fetch,
      keyed,
    }).fetch(route, url, request());
    expect([...response.headers]).toEqual([
      ["content-type", "application/json"],
    ]);
    expect(response.url).toBe("");
    expect(await response.text()).not.toContain(secret);
  }
});

it("bounds keyed request bodies", async () => {
  await denied(
    "query-rpc",
    QUERY_ROOT,
    { method: "POST", body: " ".repeat(65537) },
    env,
    "unavailable",
  );
});

it("downloads only the official SDN XML export, without credentials or caller headers", async () => {
  const xml = "<sdnList><idType>Digital Currency Address</idType></sdnList>";
  const { fetch, seen } = upstream(
    () =>
      new Response(xml, {
        headers: {
          "set-cookie": "upstream",
          location: `https://example.org/${PRIMARY}`,
        },
      }),
  );
  const egress = createProviderEgress(env, { fetch });
  expect(egress.credentialed("sanctions-screen")).toBe(true);
  expect(egress.baseUrl("sanctions-screen")).toBe(OFAC);
  const response = await egress.fetch("sanctions-screen", OFAC, {
    headers: { authorization: "caller", cookie: "caller" },
  });
  expect(await response.text()).toBe(xml);
  expect([...response.headers]).toEqual([["content-type", "application/xml"]]);
  expect(seen[0]?.url).toBe(OFAC);
  expect(seen.map((sent) => [...sent.headers])).toEqual([
    [["accept", "application/xml"]],
  ]);
});

it("refuses other SDN destinations and methods, and an unconfigured export", async () => {
  const sanctions = async (
    url: string,
    init?: RequestInit,
    bindings: Env = env,
    code = "denied",
  ) => {
    const { fetch, seen } = upstream();
    await expect(
      createProviderEgress(bindings, { fetch }).fetch(
        "sanctions-screen",
        url,
        init,
      ),
    ).rejects.toMatchObject({ name: "VeilError", code });
    expect(seen).toHaveLength(0);
  };
  for (const wrong of [
    "https://evil.example/",
    OFAC.replace("https:", "http:"),
    `${OFAC}?other=1`,
    `${OFAC}/other`,
  ])
    await sanctions(wrong);
  for (const method of ["POST", "PUT", "DELETE", "HEAD"])
    await sanctions(OFAC, { method });
  await sanctions(OFAC, undefined, {}, "unavailable");
  await sanctions(
    OFAC,
    undefined,
    { SANCTIONS_SDN_URL: "https://evil.example/" },
    "unavailable",
  );
  expect(createProviderEgress({}).baseUrl("sanctions-screen")).toBeNull();
});

it("refuses an unpinned SDN redirect and an unbounded SDN body", async () => {
  const redirect = upstream(
    () =>
      new Response(null, {
        status: 302,
        headers: { location: "https://evil.example/" },
      }),
  );
  await expect(
    createProviderEgress(env, { fetch: redirect.fetch }).fetch(
      "sanctions-screen",
      OFAC,
    ),
  ).rejects.toMatchObject({ code: "unavailable" });
  expect(redirect.seen).toHaveLength(1);
  expect(redirect.seen[0]?.redirect).toBe("manual");

  const chunk = new Uint8Array(1024 * 1024);
  const cancelled = vi.fn();
  const large = upstream(
    () =>
      new Response(
        new ReadableStream({
          pull(controller) {
            controller.enqueue(chunk);
          },
          cancel: cancelled,
        }),
      ),
  );
  await expect(
    createProviderEgress(env, { fetch: large.fetch }).fetch(
      "sanctions-screen",
      OFAC,
    ),
  ).rejects.toMatchObject({ code: "unavailable" });
  expect(cancelled).toHaveBeenCalledOnce();
});
