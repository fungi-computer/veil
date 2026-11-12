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

/**
 * Every provider whose Pi catalog runs with one plain API key against one
 * supplier base: its label, base URL, how the key is presented and the cheap
 * authenticated read that proves it. This is the single list; hosts add only
 * what they alone own (a Nango integration, a Pi catalog loader).
 */
export const catalogModelKeyProviders = {
  anthropic: {
    label: "Anthropic",
    baseUrl: "https://api.anthropic.com",
    auth: "x-api-key",
    probe: "/v1/models?limit=1",
  },
  openai: {
    label: "OpenAI",
    baseUrl: "https://api.openai.com/v1",
    auth: "bearer",
    probe: "/models",
  },
  openrouter: {
    label: "OpenRouter",
    baseUrl: "https://openrouter.ai/api/v1",
    auth: "bearer",
    probe: "/key",
  },
  google: {
    label: "Google Gemini",
    baseUrl: "https://generativelanguage.googleapis.com/v1beta",
    auth: "x-goog-api-key",
    probe: "/models?pageSize=1",
  },
  xai: {
    label: "xAI",
    baseUrl: "https://api.x.ai/v1",
    auth: "bearer",
    probe: "/models",
  },
  groq: {
    label: "Groq",
    baseUrl: "https://api.groq.com/openai/v1",
    auth: "bearer",
    probe: "/models",
  },
  mistral: {
    label: "Mistral",
    baseUrl: "https://api.mistral.ai",
    auth: "bearer",
    probe: "/v1/models",
  },
  deepseek: {
    label: "DeepSeek",
    baseUrl: "https://api.deepseek.com",
    auth: "bearer",
    probe: "/models",
  },
  cerebras: {
    label: "Cerebras",
    baseUrl: "https://api.cerebras.ai/v1",
    auth: "bearer",
    probe: "/models",
  },
  together: {
    label: "Together AI",
    baseUrl: "https://api.together.ai/v1",
    auth: "bearer",
    probe: "/models",
  },
  moonshotai: {
    label: "Moonshot AI",
    baseUrl: "https://api.moonshot.ai/v1",
    auth: "bearer",
    probe: "/models",
  },
} as const satisfies Readonly<
  Record<
    string,
    Readonly<{
      label: string;
      baseUrl: string;
      auth: "bearer" | "x-api-key" | "x-goog-api-key";
      probe: string;
    }>
  >
>;
export type CatalogModelKeyProvider = keyof typeof catalogModelKeyProviders;
export const catalogModelKeyProviderIds = Object.freeze(
  // Object.keys widens to string; the table's own keys are the union.
  Object.keys(catalogModelKeyProviders).filter(isCatalogModelKeyProvider),
);

export function isCatalogModelKeyProvider(
  value: string,
): value is CatalogModelKeyProvider {
  return Object.hasOwn(catalogModelKeyProviders, value);
}

/** The request header that carries a catalog provider's key. */
export function modelKeyAuthenticated(
  provider: CatalogModelKeyProvider,
  headers: Headers,
  apiKey: string,
): Headers {
  const next = new Headers(headers);
  const { auth } = catalogModelKeyProviders[provider];
  if (auth === "bearer") next.set("authorization", `Bearer ${apiKey}`);
  else next.set(auth, apiKey);
  return next;
}

/**
 * Canonical base URL for a sealed key. Only an OpenAI-compatible key names its
 * own base: HTTPS without credentials, query or fragment, on a public host.
 * Plain HTTP to a loopback host is accepted only with `allowLocalDev`.
 * Resolution is checked separately with `assertPublicResolution`.
 */
export function modelKeyBaseUrl(
  provider: ModelKeyProvider | CatalogModelKeyProvider,
  configured?: string | null,
  options: Readonly<{ allowLocalDev?: boolean }> = {},
): string {
  if (provider !== "openai-compatible") {
    if (configured !== undefined && configured !== null)
      throw new VeilError("invalid_input");
    return catalogModelKeyProviders[provider].baseUrl;
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

/** A stored key as an owner sees it: no secret, no custody locator. */
export type ModelKeyRecord = Readonly<{
  keyId: string;
  provider: ModelKeyProvider;
  label: string;
  createdAt: number;
  validatedAt: number;
}>;

/**
 * The neutral model-key seam every host composes: standalone Oyster over
 * Veil's credential store, the Hub over its Nango custodian. `seal` validates
 * with the provider before storing; `send` is the only place a key meets a
 * request.
 */
export type ModelKeyVault = Readonly<{
  seal: (
    input: Readonly<{ provider: string; label: string; apiKey: string }>,
  ) => Promise<ModelKeyRecord>;
  list: () => Promise<readonly ModelKeyRecord[]>;
  remove: (keyId: string) => Promise<"deleted" | "absent">;
  send: (keyId: string, request: Request) => Promise<Response>;
}>;

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
export function modelKeyTarget(
  access: Pick<ModelKeyAccess, "baseUrl">,
  request: Request,
): URL {
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
  access: Readonly<{
    provider: CatalogModelKeyProvider | "openai-compatible";
    baseUrl: string;
  }>,
  signal: AbortSignal,
): Request {
  const headers = new Headers({ accept: "application/json" });
  if (access.provider === "anthropic")
    headers.set("anthropic-version", "2023-06-01");
  const probe =
    access.provider === "openai-compatible"
      ? "/models"
      : catalogModelKeyProviders[access.provider].probe;
  return new Request(`${access.baseUrl}${probe}`, {
    method: "GET",
    headers,
    signal,
  });
}

/** Read a validation response: only an auth refusal says the key itself is bad. */
export function modelKeyValidationResult(
  status: number,
): "valid" | "rejected" | "unavailable" {
  if (status >= 200 && status < 300) return "valid";
  if (status === 401 || status === 403) return "rejected";
  return "unavailable";
}
