import { VeilError } from "./index.js";
import { assertPublicHostName, publicAddress } from "./model-key-network.js";

/** Providers a Team may bring its own API key for on hosted Fungi. */
export const modelKeyProviders = [
  "anthropic",
  "openai",
  "openrouter",
  "openai-compatible",
] as const;
export type ModelKeyProvider = (typeof modelKeyProviders)[number];

export function isModelKeyProvider(value: string): value is ModelKeyProvider {
  return modelKeyProviders.some((provider) => provider === value);
}

/** The supplier base each provider's Pi client targets. */
const providerBaseUrls = {
  anthropic: "https://api.anthropic.com",
  openai: "https://api.openai.com/v1",
  openrouter: "https://openrouter.ai/api/v1",
} as const satisfies Record<
  Exclude<ModelKeyProvider, "openai-compatible">,
  string
>;

/**
 * Canonical base URL for a sealed key. Only an OpenAI-compatible key names its
 * own base: HTTPS without credentials, query or fragment, on a public host.
 * Plain HTTP to a loopback host is accepted only with `allowLocalDev`.
 * Resolution is checked separately with `assertPublicResolution`.
 */
export function modelKeyBaseUrl(
  provider: ModelKeyProvider,
  configured?: string | null,
  options: Readonly<{ allowLocalDev?: boolean }> = {},
): string {
  if (provider !== "openai-compatible") {
    if (configured !== undefined && configured !== null)
      throw new VeilError("invalid_input");
    return providerBaseUrls[provider];
  }
  let url: URL;
  try {
    url = new URL(configured ?? "");
  } catch {
    throw new VeilError("invalid_input");
  }
  if (url.username || url.password || url.search || url.hash)
    throw new VeilError("invalid_input");
  const loopback =
    url.hostname === "localhost" ||
    (publicAddress(url.hostname) === false &&
      /^(127\.|\[::1\]$)/u.test(url.hostname));
  if (options.allowLocalDev === true && loopback) {
    if (url.protocol !== "http:" && url.protocol !== "https:")
      throw new VeilError("invalid_input");
    return url.href.replace(/\/+$/u, "");
  }
  if (url.protocol !== "https:") throw new VeilError("invalid_input");
  try {
    assertPublicHostName(url.hostname);
  } catch {
    throw new VeilError("invalid_input");
  }
  return url.href.replace(/\/+$/u, "");
}

/** Private to the Team owner and the custodian adapter; never a public field. */
export type ModelKeyAccess = Readonly<{
  locator: string;
  provider: ModelKeyProvider;
  baseUrl: string;
}>;

/**
 * Write-only custody for Team model API keys. The key enters once through
 * `seal`; nothing returns it. `send` attaches it at final egress.
 */
export type ModelKeyCustodian = Readonly<{
  seal: (
    input: Readonly<{
      teamId: string;
      /** Private custody id chosen by the owner, distinct from the public key id. */
      locator: string;
      provider: ModelKeyProvider;
      apiKey: string;
    }>,
    signal: AbortSignal,
  ) => Promise<void>;
  send: (access: ModelKeyAccess, request: Request) => Promise<Response>;
  remove: (
    access: Pick<ModelKeyAccess, "locator" | "provider">,
    signal: AbortSignal,
  ) => Promise<"deleted" | "absent">;
}>;

/** Request headers a supplier call may carry; credentials are never among them. */
const forwardedHeaders = [
  "accept",
  "content-type",
  "anthropic-version",
  "anthropic-beta",
  "openai-beta",
] as const;

/** The exact supplier target, confined below the sealed key's base URL. */
export function modelKeyTarget(access: ModelKeyAccess, request: Request): URL {
  const base = new URL(`${access.baseUrl}/`);
  let target: URL;
  try {
    target = new URL(request.url);
  } catch {
    throw new VeilError("denied");
  }
  if (
    target.origin !== base.origin ||
    !`${target.pathname}/`.startsWith(base.pathname) ||
    target.username ||
    target.password ||
    target.hash ||
    target.pathname.split("/").some((part) => part === "." || part === "..")
  )
    throw new VeilError("denied");
  if (!["GET", "POST"].includes(request.method)) throw new VeilError("denied");
  return target;
}

/** Copy only supplier-meaningful headers; the caller's auth is dropped. */
export function modelKeyForwardedHeaders(request: Request): Headers {
  const headers = new Headers();
  for (const name of forwardedHeaders) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  return headers;
}

/** A cheap authenticated read that proves a key works without spending tokens. */
export function modelKeyValidationRequest(
  access: Pick<ModelKeyAccess, "provider" | "baseUrl">,
  signal: AbortSignal,
): Request {
  const path = access.provider === "openrouter" ? "/key" : "/models";
  const url =
    access.provider === "anthropic"
      ? `${access.baseUrl}/v1/models?limit=1`
      : `${access.baseUrl}${path}`;
  const headers = new Headers({ accept: "application/json" });
  if (access.provider === "anthropic")
    headers.set("anthropic-version", "2023-06-01");
  return new Request(url, { method: "GET", headers, signal });
}

/** Read a validation response: only an auth refusal says the key itself is bad. */
export function modelKeyValidationResult(
  status: number,
): "valid" | "rejected" | "unavailable" {
  if (status >= 200 && status < 300) return "valid";
  if (status === 401 || status === 403) return "rejected";
  return "unavailable";
}
