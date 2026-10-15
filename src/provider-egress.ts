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
}>;

export type ProviderRoute =
  "camel" | "ai-gateway" | "parallel" | "ai-gateway-logs";

const CAMEL_BASE = "https://stream.camelai.com/v1";
const PARALLEL_BASE = "https://api.parallel.ai";
const GATEWAY_ORIGIN = "https://gateway.ai.cloudflare.com";
const CLOUDFLARE_API_ORIGIN = "https://api.cloudflare.com";

type Target = Readonly<{ base: URL; credential: string }>;

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
  credential: string,
): void {
  for (const name of [
    "authorization",
    "x-api-key",
    "cf-aig-authorization",
    "proxy-authorization",
  ])
    headers.delete(name);
  switch (route) {
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
    /** Whether this route's credential is configured; reveals no value. */
    credentialed(route: ProviderRoute): boolean {
      switch (route) {
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
     * credential. Redirects are never followed, so a redirect cannot carry
     * the key to another origin (workerd has no `error` mode; `manual` hands
     * the 3xx back instead).
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
