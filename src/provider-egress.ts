import { z } from "zod";
import { VeilError } from "./index.js";

/**
 * Provider egress, `veil.fetch` for Fungi's own platform keys (V1b). The Hub
 * names a route and hands over a request that carries no credential; Veil
 * checks the destination against that route's allowed origin and path, then
 * attaches the platform key itself. The key value never crosses back: not in a
 * returned value, not in a thrown error (only fixed `VeilError` codes), and
 * not in anything this module logs (it logs nothing).
 *
 * Routes:
 * - `camel`: Camel's hosted stream, `Authorization: Bearer`.
 * - `ai-gateway`: Cloudflare AI Gateway's OpenAI-compatible route, with the
 *   gateway token as `cf-aig-authorization` and no `Authorization`.
 * - `parallel`: Parallel Search, directly or through the AI Gateway's
 *   `/parallel` route, with `x-api-key`.
 * - `ai-gateway-logs`: Cloudflare's API log read used for usage
 *   reconciliation, `Authorization: Bearer` with the gateway token.
 * - `solana-rpc` / `solana-rpc-fallback`: finalized snapshot reads through
 *   Helius / QuickNode, with private query / path credentials.
 * - `sanctions-screen`: the official OFAC SDN XML export, without a key.
 */

/** Private Worker bindings read only here; never Team storage or responses. */
export type ProviderKeyBindings = Readonly<{
  CAMEL_API_KEY?: string;
  /** Cloudflare API token; authorizes AI Gateway calls and log reads. */
  AI_GATEWAY_AUTH_TOKEN?: string;
  PARALLEL_API_KEY?: string;
  /** Cloudflare account that owns the gateway; routes are scoped to it. */
  AI_GATEWAY_ACCOUNT_ID?: string;
  AI_GATEWAY_ID?: string;
  /** Credential-free Helius mainnet root; the key is a separate Worker secret. */
  SOLANA_RPC_URL?: string;
  SOLANA_RPC_API_KEY?: string;
  /** Credential-free QuickNode Solana mainnet root; token is a Worker secret. */
  SOLANA_RPC_FALLBACK_URL?: string;
  SOLANA_RPC_FALLBACK_API_KEY?: string;
  /** Opt-in to the pinned public OFAC SDN XML export. No API key is needed. */
  SANCTIONS_SDN_URL?: string;
}>;

export type ProviderRoute =
  | "camel"
  | "ai-gateway"
  | "parallel"
  | "ai-gateway-logs"
  | "solana-rpc"
  | "solana-rpc-fallback"
  | "sanctions-screen";

const CAMEL_BASE = "https://stream.camelai.com/v1";
const PARALLEL_BASE = "https://api.parallel.ai";
const GATEWAY_ORIGIN = "https://gateway.ai.cloudflare.com";
const CLOUDFLARE_API_ORIGIN = "https://api.cloudflare.com";
const HELIUS_BASE = "https://mainnet.helius-rpc.com/";
const OFAC_SDN =
  "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML";
const OFAC_DOWNLOAD_ORIGIN =
  "https://wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com";

type Target = Readonly<{ base: URL; credential?: string }>;

// Single read-only JSON-RPC calls used by the finalized holdings/lock reader.
// Zod owns JSON envelope decoding; the holdings owner owns params and results.
const snapshotCall = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: z.union([z.string(), z.number()]),
    method: z.enum([
      "getAccountInfo",
      "getMultipleAccounts",
      "getProgramAccounts",
      "getTokenSupply",
      "getSlot",
    ]),
    params: z.array(z.unknown()).optional(),
  })
  .strict();

function snapshotRoute(route: ProviderRoute): boolean {
  return (
    route === "solana-rpc" ||
    route === "solana-rpc-fallback" ||
    route === "sanctions-screen"
  );
}

const present = (value: string | undefined): string | undefined => {
  const trimmed = value?.trim();
  return trimmed === undefined || trimmed === "" ? undefined : trimmed;
};

/** The one AI Gateway origin-and-path scope, or `undefined` when unnamed. */
function gatewayScope(env: ProviderKeyBindings): string | undefined {
  const account = present(env.AI_GATEWAY_ACCOUNT_ID);
  const gateway = present(env.AI_GATEWAY_ID);
  if (account === undefined || gateway === undefined) return undefined;
  return `${GATEWAY_ORIGIN}/v1/${encodeURIComponent(account)}/${encodeURIComponent(gateway)}`;
}

/** The destination and credential for a route; `undefined` if either is missing. */
function target(
  env: ProviderKeyBindings,
  route: ProviderRoute,
): Target | undefined {
  switch (route) {
    case "solana-rpc":
    case "solana-rpc-fallback": {
      const primary = route === "solana-rpc";
      const raw = present(
        primary ? env.SOLANA_RPC_URL : env.SOLANA_RPC_FALLBACK_URL,
      );
      const credential = present(
        primary ? env.SOLANA_RPC_API_KEY : env.SOLANA_RPC_FALLBACK_API_KEY,
      );
      if (raw === undefined || credential === undefined) return undefined;
      if (!URL.canParse(raw)) return undefined;
      const base = new URL(raw);
      if (
        base.protocol !== "https:" ||
        base.username ||
        base.password ||
        base.port ||
        base.pathname !== "/" ||
        base.search ||
        base.hash
      )
        return undefined;
      if (
        primary
          ? base.href !== HELIUS_BASE
          : !/^[a-z0-9-]+\.solana-mainnet\.quiknode\.pro$/u.test(base.hostname)
      )
        return undefined;
      return { base, credential };
    }
    case "sanctions-screen":
      return present(env.SANCTIONS_SDN_URL) === OFAC_SDN
        ? { base: new URL(OFAC_SDN) }
        : undefined;
    case "camel": {
      const credential = present(env.CAMEL_API_KEY);
      return credential === undefined
        ? undefined
        : { base: new URL(CAMEL_BASE), credential };
    }
    case "ai-gateway": {
      const credential = present(env.AI_GATEWAY_AUTH_TOKEN);
      const scope = gatewayScope(env);
      return credential === undefined || scope === undefined
        ? undefined
        : { base: new URL(`${scope}/compat`), credential };
    }
    case "parallel": {
      const credential = present(env.PARALLEL_API_KEY);
      if (credential === undefined) return undefined;
      const scope = gatewayScope(env);
      return {
        base: new URL(
          scope === undefined ? PARALLEL_BASE : `${scope}/parallel`,
        ),
        credential,
      };
    }
    case "ai-gateway-logs": {
      const credential = present(env.AI_GATEWAY_AUTH_TOKEN);
      const account = present(env.AI_GATEWAY_ACCOUNT_ID);
      const gateway = present(env.AI_GATEWAY_ID);
      return credential === undefined ||
        account === undefined ||
        gateway === undefined
        ? undefined
        : {
            base: new URL(
              `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${encodeURIComponent(account)}/ai-gateway/gateways/${encodeURIComponent(gateway)}/logs`,
            ),
            credential,
          };
    }
  }
}

/** `url` is the base itself or lies beneath it, on the same https origin. */
function within(url: URL, base: URL): boolean {
  if (url.protocol !== "https:" || url.origin !== base.origin) return false;
  if (url.username !== "" || url.password !== "") return false;
  const root = base.pathname.replace(/\/+$/u, "");
  return url.pathname === root || url.pathname.startsWith(`${root}/`);
}

/** Replace whatever credential the caller sent with this route's own. */
function authorize(
  route: ProviderRoute,
  headers: Headers,
  credential: string | undefined,
): void {
  if (credential === undefined) throw new VeilError("unavailable");
  for (const name of [
    "authorization",
    "x-api-key",
    "cf-aig-authorization",
    "proxy-authorization",
  ])
    headers.delete(name);
  switch (route) {
    case "solana-rpc":
    case "solana-rpc-fallback":
    case "sanctions-screen":
      // These doors construct their own headers and URL below.
      return;
    case "camel":
    case "ai-gateway-logs":
      headers.set("authorization", `Bearer ${credential}`);
      return;
    case "ai-gateway":
      headers.set("cf-aig-authorization", `Bearer ${credential}`);
      return;
    case "parallel":
      headers.set("x-api-key", credential);
      return;
  }
}

/** A bounded body, before JSON decoding or returning a provider response. */
async function boundedText(
  message: Request | Response,
  limit: number,
): Promise<string> {
  const reader = message.body?.getReader();
  if (reader === undefined) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      const chunk: unknown = part.value;
      if (!(chunk instanceof Uint8Array)) throw new VeilError("unavailable");
      size += chunk.byteLength;
      if (size > limit) throw new VeilError("unavailable");
      chunks.push(chunk);
    }
    return await new Blob(chunks).text();
  } finally {
    try {
      await reader.cancel();
    } finally {
      reader.releaseLock();
    }
  }
}

/** Fixed, non-streaming snapshot doors never return upstream headers or URLs. */
async function fetchSnapshot(
  route: ProviderRoute,
  resolved: Target,
  request: Request,
  transport: typeof globalThis.fetch,
): Promise<Response> {
  try {
    const url = new URL(request.url);
    if (url.href !== resolved.base.href) throw new VeilError("denied");
    const screening = route === "sanctions-screen";
    if (request.method !== (screening ? "GET" : "POST"))
      throw new VeilError("denied");
    let body: string | undefined;
    if (!screening) {
      body = await boundedText(request, 64 * 1024);
      let envelope: unknown;
      try {
        envelope = JSON.parse(body);
      } catch {
        throw new VeilError("denied");
      }
      if (!snapshotCall.safeParse(envelope).success)
        throw new VeilError("denied");
    }
    const destination = new URL(resolved.base);
    const key = resolved.credential;
    if (!screening) {
      if (key === undefined) throw new VeilError("unavailable");
      if (route === "solana-rpc") destination.searchParams.set("api-key", key);
      else destination.pathname = `/${encodeURIComponent(key)}/`;
    }
    const init: RequestInit = {
      method: request.method,
      headers: screening
        ? { accept: "application/xml" }
        : {
            accept: "application/json",
            "content-type": "application/json",
          },
      signal: request.signal,
      redirect: "manual",
    };
    if (body !== undefined) init.body = body;
    let response = await transport(new Request(destination, init));
    // OFAC publishes a signed S3 download URL. Only this anonymous GET door
    // may follow that one observed 302; the next response must succeed.
    if (screening && response.status === 302) {
      const location = response.headers.get("location");
      await response.body?.cancel();
      if (
        location === null ||
        location.length > 8192 ||
        !URL.canParse(location)
      )
        throw new VeilError("unavailable");
      const download = new URL(location);
      if (
        download.origin !== OFAC_DOWNLOAD_ORIGIN ||
        download.username !== "" ||
        download.password !== "" ||
        !download.pathname.startsWith("/Published/") ||
        !download.pathname.endsWith("/SDN.XML") ||
        download.hash !== ""
      )
        throw new VeilError("unavailable");
      request.signal.throwIfAborted();
      response = await transport(
        new Request(download, {
          method: "GET",
          headers: { accept: "application/xml" },
          signal: request.signal,
          redirect: "manual",
        }),
      );
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new VeilError("unavailable");
    }
    const text = await boundedText(response, 64 * 1024 * 1024);
    if (
      key !== undefined &&
      [key, encodeURIComponent(key), JSON.stringify(key).slice(1, -1)].some(
        (echo) => text.includes(echo),
      )
    )
      throw new VeilError("unavailable");
    return new Response(text, {
      status: response.status,
      headers: {
        "content-type": screening ? "application/xml" : "application/json",
      },
    });
  } catch (error) {
    // Even aborted transports can include a credential-bearing URL in errors.
    if (error instanceof VeilError) throw error;
    throw new VeilError("unavailable");
  }
}

/**
 * The provider-key door. `fetch` is the transport the authorized request is
 * finally sent on (a test double, or the Hub's telemetry-wrapped fetch).
 */
export function createProviderEgress(
  env: ProviderKeyBindings,
  options: Readonly<{ fetch?: typeof globalThis.fetch }> = {},
) {
  const transport: typeof globalThis.fetch =
    options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  return {
    /** Whether required custody/configuration is present; reveals no value. */
    credentialed(route: ProviderRoute): boolean {
      switch (route) {
        case "solana-rpc":
        case "solana-rpc-fallback":
        case "sanctions-screen":
          return target(env, route) !== undefined;
        case "camel":
          return present(env.CAMEL_API_KEY) !== undefined;
        case "parallel":
          return present(env.PARALLEL_API_KEY) !== undefined;
        case "ai-gateway":
        case "ai-gateway-logs":
          return present(env.AI_GATEWAY_AUTH_TOKEN) !== undefined;
      }
    },
    /** The route's public base URL, or `null` while it is not configured. */
    baseUrl(route: ProviderRoute): string | null {
      const resolved = target(env, route);
      return resolved === undefined
        ? null
        : resolved.base.href.replace(/\/+$/u, "");
    },
    /**
     * Send a credential-free request to a route. Refuses (`denied`) any
     * destination outside the route and (`unavailable`) a route with no
     * credential. Credentialed routes never follow redirects (workerd has no
     * `error` mode; `manual` hands the 3xx back instead). Only the anonymous
     * sanctions GET may follow one pinned OFAC government-S3 302.
     */
    async fetch(
      route: ProviderRoute,
      input: string | URL | Request,
      init?: RequestInit,
    ): Promise<Response> {
      const resolved = target(env, route);
      if (resolved === undefined) throw new VeilError("unavailable");
      let request: Request;
      try {
        request = new Request(input, init);
      } catch {
        // Malformed, or a URL carrying userinfo: nothing Veil will send a key to.
        throw new VeilError("denied");
      }
      if (!within(new URL(request.url), resolved.base))
        throw new VeilError("denied");
      if (snapshotRoute(route))
        return fetchSnapshot(route, resolved, request, transport);
      const headers = new Headers(request.headers);
      authorize(route, headers, resolved.credential);
      try {
        return await transport(
          new Request(request, { headers, redirect: "manual" }),
        );
      } catch (error) {
        // A cancelled call keeps its own reason; anything else is sanitized so
        // a transport message can never carry request bytes back to the caller.
        if (request.signal.aborted) throw error;
        throw new VeilError("unavailable");
      }
    },
  };
}
export type ProviderEgress = ReturnType<typeof createProviderEgress>;

/** A `fetch` bound to one route, for consumers that take a plain fetch. */
export function providerFetch(
  egress: ProviderEgress,
  route: ProviderRoute,
): typeof globalThis.fetch {
  return (input, init) => egress.fetch(route, input, init);
}
