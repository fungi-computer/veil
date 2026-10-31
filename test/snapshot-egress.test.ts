import { expect, it, vi } from "vitest";
import { VeilError } from "../src/index.js";
import { configuredProviderEgress } from "../src/gatekeeper.js";
import {
  createProviderEgress,
  providerFetch,
  type ProviderKeyBindings,
  type ProviderRoute,
} from "../src/provider-egress.js";

const PRIMARY = "synthetic-helius-secret";
const FALLBACK = "synthetic-quicknode-secret";
const HELIUS = "https://mainnet.helius-rpc.com/";
const QUICKNODE = "https://example.solana-mainnet.quiknode.pro/";
const OFAC =
  "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML";
const env: ProviderKeyBindings = {
  SOLANA_RPC_URL: HELIUS,
  SOLANA_RPC_API_KEY: PRIMARY,
  SOLANA_RPC_FALLBACK_URL: QUICKNODE,
  SOLANA_RPC_FALLBACK_API_KEY: FALLBACK,
  SANCTIONS_SDN_URL: OFAC,
};
function withoutBinding(name: keyof ProviderKeyBindings): ProviderKeyBindings {
  return Object.fromEntries(
    Object.entries(env).filter(([key]) => key !== name),
  );
}
const rpcRoutes = [
  ["solana-rpc", HELIUS, PRIMARY],
  ["solana-rpc-fallback", QUICKNODE, FALLBACK],
] as const;
const routes: readonly (readonly [ProviderRoute, string])[] = [
  ...rpcRoutes.map(([route, url]) => [route, url] as const),
  ["sanctions-screen", OFAC],
];
const call = (method = "getSlot") => ({
  method: "POST",
  body: JSON.stringify({
    jsonrpc: "2.0",
    id: "snapshot-1",
    method,
    params: [],
  }),
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
  route: ProviderRoute,
  url: string,
  init?: RequestInit,
  bindings = env,
  code = "denied",
) {
  const { fetch, seen } = upstream();
  await expect(
    createProviderEgress(bindings, { fetch }).fetch(route, url, init),
  ).rejects.toMatchObject({ name: "VeilError", code });
  expect(seen).toHaveLength(0);
}

it("pins primary and fallback read-only RPCs and attaches keys only inside Veil", async () => {
  for (const [route, url, secret] of rpcRoutes) {
    const { fetch, seen } = upstream();
    const egress = configuredProviderEgress(env, { fetch });
    expect(egress.credentialed(route)).toBe(true);
    expect(egress.baseUrl(route)).toBe(url.replace(/\/$/u, ""));
    const bound = providerFetch(egress, route);
    for (const method of [
      "getAccountInfo",
      "getMultipleAccounts",
      "getProgramAccounts",
      "getTokenSupply",
      "getSlot",
    ]) {
      const response = await bound(url, {
        ...call(method),
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
    for (const request of seen) {
      const destination = new URL(request.url);
      expect(destination.origin).toBe(new URL(url).origin);
      if (route === "solana-rpc") {
        expect(destination.pathname).toBe("/");
        expect(destination.searchParams.get("api-key")).toBe(secret);
      } else {
        expect(destination.pathname).toBe(`/${secret}/`);
        expect(destination.search).toBe("");
      }
      expect([...request.headers.keys()].sort()).toEqual([
        "accept",
        "content-type",
      ]);
      expect(request.redirect).toBe("manual");
    }
    expect(JSON.stringify(egress)).not.toContain(secret);
    expect(egress.baseUrl(route)).not.toContain(secret);
  }
});

it("downloads only the official SDN XML export, without credentials or caller headers", async () => {
  const xml =
    "<sdnList><idType>Digital Currency Address - SOL</idType></sdnList>";
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
  expect(seen.map((request) => [...request.headers])).toEqual([
    [["accept", "application/xml"]],
  ]);
});

it("refuses every other origin, path, query, port and HTTP method before fetch", async () => {
  for (const [route, url] of routes) {
    const init = route === "sanctions-screen" ? undefined : call();
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
      await denied(route, wrong, init);
    for (const method of ["GET", "POST", "PUT", "DELETE", "HEAD"]) {
      if (method === (route === "sanctions-screen" ? "GET" : "POST")) continue;
      await denied(route, url, { method });
    }
  }
  // Another valid QuickNode endpoint is not this environment's pinned host.
  await denied(
    "solana-rpc-fallback",
    QUICKNODE.replace("example.", "other."),
    call(),
  );
});

it("refuses transaction, arbitrary, batch and malformed JSON-RPC calls", async () => {
  for (const [route, url] of rpcRoutes) {
    for (const method of [
      "sendTransaction",
      "simulateTransaction",
      "requestAirdrop",
      "getBalance",
    ])
      await denied(route, url, call(method));
    for (const body of [
      JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "getSlot" }]),
      JSON.stringify({ jsonrpc: "1.0", id: 1, method: "getSlot" }),
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getSlot", extra: true }),
    ])
      await denied(route, url, { method: "POST", body });
    await denied(route, url, { method: "POST", body: "{" });
  }
});

it("missing or invalid configuration refuses without contacting any provider", async () => {
  for (const [route, url] of routes) {
    await denied(route, url, undefined, {}, "unavailable");
    const egress = createProviderEgress({});
    expect(egress.credentialed(route)).toBe(false);
    expect(egress.baseUrl(route)).toBeNull();
  }
  for (const bindings of [
    withoutBinding("SOLANA_RPC_API_KEY"),
    withoutBinding("SOLANA_RPC_URL"),
    { ...env, SOLANA_RPC_URL: "invalid url" },
    { ...env, SOLANA_RPC_URL: `${HELIUS}?api-key=${PRIMARY}` },
    { ...env, SOLANA_RPC_URL: "https://api.mainnet-beta.solana.com/" },
  ])
    await denied("solana-rpc", HELIUS, call(), bindings, "unavailable");
  for (const bindings of [
    withoutBinding("SOLANA_RPC_FALLBACK_API_KEY"),
    withoutBinding("SOLANA_RPC_FALLBACK_URL"),
    { ...env, SOLANA_RPC_FALLBACK_URL: `${QUICKNODE}${FALLBACK}/` },
    { ...env, SOLANA_RPC_FALLBACK_URL: "https://evil.example/" },
    { ...env, SOLANA_RPC_FALLBACK_URL: QUICKNODE.replace("mainnet", "devnet") },
  ])
    await denied(
      "solana-rpc-fallback",
      QUICKNODE,
      call(),
      bindings,
      "unavailable",
    );
  await denied(
    "sanctions-screen",
    OFAC,
    undefined,
    { SANCTIONS_SDN_URL: "https://evil.example/" },
    "unavailable",
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
        createProviderEgress(env, { fetch }).fetch(route, url, call()),
      ).rejects.toMatchObject({ code: "unavailable", message: "unavailable" });
    }
    const controller = new AbortController();
    const fetch: typeof globalThis.fetch = () => {
      controller.abort();
      return Promise.reject(new Error(`upstream failed: ${url}${secret}`));
    };
    const egress = createProviderEgress(env, { fetch });
    const error: unknown = await egress
      .fetch(route, url, { ...call(), signal: controller.signal })
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
    }).fetch(route, url, call());
    expect([...response.headers]).toEqual([
      ["content-type", "application/json"],
    ]);
    expect(response.url).toBe("");
    expect(await response.text()).not.toContain(secret);
  }
});

it("bounds request and response bodies and refuses an unpinned SDN redirect", async () => {
  await denied(
    "solana-rpc",
    HELIUS,
    { method: "POST", body: " ".repeat(65537) },
    env,
    "unavailable",
  );
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
