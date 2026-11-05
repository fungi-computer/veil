import {
  createOpenApiDoor,
  type OpenApiCredentialKeyring,
  type OpenApiCredentialStore,
  type OpenApiOAuthProvider,
  type OpenApiDoorOptions,
} from "./openapi.js";
import { createOpenApiEffects, type OpenApiEffects } from "./openapi-effect.js";
import { createDnsOverHttpsResolver } from "./model-key-network.js";
import type { PublicConnect } from "./public-fetch.js";
import {
  ConnectionsError,
  type CustodyProvider,
} from "./connections/contract.js";
import { createGitHubAppCustody, type GitHubAppCustody } from "./github-app.js";
import {
  createNangoCustody,
  type ConnectionsCustodian,
} from "./connections/nango.js";
import { createWebhookTriggerSecrets } from "./webhook-trigger-secrets.js";
import { createNangoModelKeyCustodian } from "./nango-model-keys.js";
import { createNangoWorldSeatCustodian } from "./nango-world-seat.js";
import { worldSeatEndpoint, type WorldSeatCustodian } from "./world-seat.js";
import type { ModelKeyCustodian } from "./model-keys.js";
import {
  createModelKeyEgress,
  createModelKeyGrants,
  type ModelKeyGrants,
} from "./model-key-grants.js";
import { VeilError } from "./index.js";
import {
  createProviderEgress,
  providerFetch,
  type ProviderEgress,
  type ProviderKeyBindings,
  type ProviderRoute,
} from "./provider-egress.js";
import * as Schema from "effect/Schema";
import * as Exit from "effect/Exit";

/**
 * The Gatekeeper: the one place the Hub's Nango key, webhook signing key,
 * provider/model-key integration ids, and platform provider keys (Camel, the
 * AI Gateway token, Parallel) are read out of the Worker environment and
 * turned into a custodian or egress. These `configured*` functions are the custody
 * boundary (`V1`): the Hub hands them its own `env` object opaquely and gets
 * back an opaque custodian/egress handle, never the secret values themselves.
 * No file outside `packages/veil` may read `env.NANGO_*` or
 * `env.WEBHOOK_TRIGGER_MASTER_KEY`, `env.CAMEL_API_KEY`,
 * `env.AI_GATEWAY_AUTH_TOKEN` or `env.PARALLEL_API_KEY` directly; the static
 * boundary test `apps/hub/test/veil-custody-boundary.test.ts` enforces it.
 * Hub code reaches a provider only through `configuredProviderEgress`.
 */

export { providerFetch };
export type { ProviderEgress, ProviderRoute };
export type { ConnectionsCustodian };

/** Private Worker bindings, never Team storage or public response fields. */
export type VeilBindings = ProviderKeyBindings &
  Readonly<{
    WEBHOOK_TRIGGER_MASTER_KEY?: string;
    /** Dedicated custody root for Team OpenAPI API-key/bearer credentials. */
    OPENAPI_CREDENTIAL_MASTER_KEY?: string;
    OPENAPI_CREDENTIAL_KEY_ID?: string;
    NANGO_SERVER_URL?: string;
    NANGO_API_KEY?: string;
    NANGO_WEBHOOK_SIGNING_KEY?: string;
    /** The GitHub REST sign-in integration; it joins the connections sign-in list. */
    NANGO_GITHUB_INTEGRATION_ID?: string;
    /** The Nango `github-app` integration that hands a Computer its installation token. */
    NANGO_GITHUB_APP_INTEGRATION_ID?: string;
    /** API-key integration that holds pasted credentials for Team connections. */
    NANGO_CONNECTIONS_INTEGRATION_ID?: string;
    /**
     * Nango integrations an owner may sign in through for connections, as a
     * JSON object from integration id to `{ "apiOrigins": ["https://…"] }`:
     * the only origins that integration's credential is sent to.
     */
    NANGO_CONNECTIONS_OAUTH_INTEGRATIONS?: string;
    /** Public Connect UI base that Nango's issued links must stay under. */
    NANGO_CONNECT_BASE_URL?: string;
    /** Public Nango API origin the Connect UI in the browser must call. */
    NANGO_PUBLIC_API_URL?: string;
    /** Nango API-key integrations holding Team and personal model keys. */
    NANGO_ANTHROPIC_KEY_INTEGRATION_ID?: string;
    NANGO_OPENAI_KEY_INTEGRATION_ID?: string;
    NANGO_OPENROUTER_KEY_INTEGRATION_ID?: string;
    /** A bearer-token integration used with a per-key base URL override. */
    NANGO_OPENAI_COMPATIBLE_KEY_INTEGRATION_ID?: string;
    /** A bearer-token integration holding App world-seat tokens. */
    NANGO_WORLD_INTEGRATION_ID?: string;
    /**
     * Exactly `enabled` only in a local/dev Hub (the checked-in local Worker
     * config). It admits a loopback world seat endpoint; production never sets
     * it and no URL can turn it on.
     */
    HUB_LOCAL_MODE?: string;
  }>;

/**
 * Optional Nango custody for Team connections. A Hub with none of the Nango
 * bindings keeps sealed custody and still connects OAuth MCP and OpenAPI.
 */
export function configuredConnectionsCustody(
  env: VeilBindings,
): ConnectionsCustodian | undefined {
  if (
    !env.NANGO_SERVER_URL ||
    !env.NANGO_API_KEY ||
    !env.NANGO_WEBHOOK_SIGNING_KEY ||
    !env.NANGO_CONNECT_BASE_URL ||
    !env.NANGO_PUBLIC_API_URL ||
    !env.NANGO_CONNECTIONS_INTEGRATION_ID
  )
    return undefined;
  try {
    return createNangoCustody({
      serverUrl: env.NANGO_SERVER_URL,
      apiKey: env.NANGO_API_KEY,
      webhookSigningKey: env.NANGO_WEBHOOK_SIGNING_KEY,
      staticIntegrationId: env.NANGO_CONNECTIONS_INTEGRATION_ID,
      connectBaseUrl: env.NANGO_CONNECT_BASE_URL,
      publicApiUrl: env.NANGO_PUBLIC_API_URL,
    });
  } catch {
    throw new VeilError("unavailable");
  }
}

/** GitHub's REST API: the only place the GitHub REST integration's token may go. */
const GITHUB_REST_ORIGIN = "https://api.github.com";

const custodyProvidersJson = Schema.fromJsonString(
  Schema.Record(
    Schema.String.pipe(
      Schema.check(Schema.isPattern(/^[A-Za-z0-9_.:-]{1,128}$/u)),
    ),
    Schema.Struct({
      apiOrigins: Schema.Array(Schema.String).pipe(
        Schema.check(Schema.isMinLength(1), Schema.isMaxLength(16)),
      ),
    }),
  ),
);
const isHttpsOrigin = (value: string) =>
  URL.canParse(value) &&
  new URL(value).protocol === "https:" &&
  new URL(value).origin === value;

/**
 * The Nango integrations an owner may sign in through for connections, each
 * pinned to the origins its credential may reach. Absent or malformed means
 * none: a sign-in through an undeclared integration is refused, never guessed.
 */
export function configuredConnectionsCustodyProviders(
  env: VeilBindings,
): Readonly<Record<string, CustodyProvider>> {
  const raw = env.NANGO_CONNECTIONS_OAUTH_INTEGRATIONS;
  const decoded =
    raw === undefined || raw.trim() === ""
      ? undefined
      : Schema.decodeUnknownExit(custodyProvidersJson)(raw);
  const operator =
    decoded === undefined || Exit.isFailure(decoded) ? {} : decoded.value;
  const declared: Record<string, CustodyProvider> = {};
  for (const [id, provider] of Object.entries(operator))
    if (provider.apiOrigins.every(isHttpsOrigin)) declared[id] = provider;
  // GitHub REST is pinned to its API host whatever the operator declared.
  const rest = env.NANGO_GITHUB_INTEGRATION_ID;
  if (rest !== undefined && rest !== "")
    declared[rest] = { apiOrigins: [GITHUB_REST_ORIGIN] };
  const app = configuredGitHubAppIntegration(env);
  return Object.fromEntries(
    Object.entries(declared).filter(([id]) => id !== app),
  );
}

/**
 * The Nango `github-app` integration through which a Computer's git gets its
 * installation token. It is its own thing: never in the generic list, and
 * never the same integration as GitHub REST.
 */
export function configuredGitHubAppIntegration(
  env: VeilBindings,
): string | undefined {
  const id = env.NANGO_GITHUB_APP_INTEGRATION_ID;
  if (id === undefined || id === "" || id === env.NANGO_GITHUB_INTEGRATION_ID)
    return undefined;
  return id;
}

/** Nango's GitHub App custody for Computers; absent when any binding is. */
export function configuredGitHubAppCustody(
  env: VeilBindings,
): GitHubAppCustody | undefined {
  const appIntegrationId = configuredGitHubAppIntegration(env);
  if (
    appIntegrationId === undefined ||
    !env.NANGO_SERVER_URL ||
    !env.NANGO_API_KEY ||
    !env.NANGO_WEBHOOK_SIGNING_KEY ||
    !env.NANGO_CONNECT_BASE_URL ||
    !env.NANGO_PUBLIC_API_URL ||
    !env.NANGO_CONNECTIONS_INTEGRATION_ID
  )
    return undefined;
  try {
    return createGitHubAppCustody({
      serverUrl: env.NANGO_SERVER_URL,
      apiKey: env.NANGO_API_KEY,
      webhookSigningKey: env.NANGO_WEBHOOK_SIGNING_KEY,
      staticIntegrationId: env.NANGO_CONNECTIONS_INTEGRATION_ID,
      connectBaseUrl: env.NANGO_CONNECT_BASE_URL,
      publicApiUrl: env.NANGO_PUBLIC_API_URL,
      appIntegrationId,
    });
  } catch {
    throw new VeilError("unavailable");
  }
}

/**
 * `veil.fetch` for platform provider keys. The Hub names a route and sends a
 * credential-free request; Veil checks the destination and attaches the key.
 * `fetch` is only the final transport (telemetry, or a test double).
 */
export function configuredProviderEgress(
  env: VeilBindings,
  options: Readonly<{ fetch?: typeof globalThis.fetch }> = {},
): ProviderEgress {
  return createProviderEgress(env, options);
}

/** The Worker secret is the only custody root for per-trigger signing bytes. */
export function configuredWebhookTriggerSecrets(env: VeilBindings) {
  if (!env.WEBHOOK_TRIGGER_MASTER_KEY) return { kind: "unavailable" as const };
  try {
    return {
      kind: "ready" as const,
      custodian: createWebhookTriggerSecrets(env.WEBHOOK_TRIGGER_MASTER_KEY),
    };
  } catch (cause) {
    return { kind: "unavailable" as const, cause };
  }
}

/** Model API keys use their own integrations; none are required to boot. */
export function configuredModelKeyCustodian(
  env: VeilBindings,
): ModelKeyCustodian {
  if (!env.NANGO_SERVER_URL || !env.NANGO_API_KEY)
    throw new VeilError("unavailable");
  const integrations: Partial<
    Record<"anthropic" | "openai" | "openrouter" | "openai-compatible", string>
  > = {};
  if (env.NANGO_ANTHROPIC_KEY_INTEGRATION_ID)
    integrations.anthropic = env.NANGO_ANTHROPIC_KEY_INTEGRATION_ID;
  if (env.NANGO_OPENAI_KEY_INTEGRATION_ID)
    integrations.openai = env.NANGO_OPENAI_KEY_INTEGRATION_ID;
  if (env.NANGO_OPENROUTER_KEY_INTEGRATION_ID)
    integrations.openrouter = env.NANGO_OPENROUTER_KEY_INTEGRATION_ID;
  if (env.NANGO_OPENAI_COMPATIBLE_KEY_INTEGRATION_ID)
    integrations["openai-compatible"] =
      env.NANGO_OPENAI_COMPATIBLE_KEY_INTEGRATION_ID;
  return createNangoModelKeyCustodian({
    serverUrl: env.NANGO_SERVER_URL,
    apiKey: env.NANGO_API_KEY,
    integrations,
  });
}

/**
 * Model-key grants are sealed under a key derived from the custodian's own
 * Nango credential, so only a holder of custody can issue or open one.
 */
export function configuredModelKeyGrants(env: VeilBindings): ModelKeyGrants {
  if (!env.NANGO_API_KEY) throw new VeilError("unavailable");
  return createModelKeyGrants({ custodySecret: env.NANGO_API_KEY });
}

/** World-seat tokens use their own integration; it is not required to boot. */
export function configuredWorldSeatCustodian(
  env: VeilBindings,
): WorldSeatCustodian {
  if (
    !env.NANGO_SERVER_URL ||
    !env.NANGO_API_KEY ||
    !env.NANGO_WORLD_INTEGRATION_ID
  )
    throw new VeilError("unavailable");
  return createNangoWorldSeatCustodian({
    serverUrl: env.NANGO_SERVER_URL,
    apiKey: env.NANGO_API_KEY,
    integrationId: env.NANGO_WORLD_INTEGRATION_ID,
    allowLocalDev: env.HUB_LOCAL_MODE === "enabled",
  });
}

/** The seat endpoint rule for this host: public HTTPS, or loopback when local. */
export function configuredWorldSeatEndpoint(
  env: VeilBindings,
): (endpoint: string) => string {
  const allowLocalDev = env.HUB_LOCAL_MODE === "enabled";
  return (endpoint) => worldSeatEndpoint(endpoint, { allowLocalDev });
}

/** Final model egress a runner reaches with a delivered grant, never via TeamDO. */
export function configuredModelKeyEgress(
  env: VeilBindings,
  options: Readonly<{
    ownerIsMember: Parameters<typeof createModelKeyEgress>[0]["ownerIsMember"];
  }>,
) {
  return createModelKeyEgress({
    grants: configuredModelKeyGrants(env),
    custodian: () => configuredModelKeyCustodian(env),
    ownerIsMember: options.ownerIsMember,
  });
}

/** The decoded key must name an integration this host runs a sign-in through;
 * the maintained custodian then verifies the original signed body. The GitHub
 * App integration settles only a Computer's git, a generic one only a
 * connection: neither can settle the other's attempt. */
export async function verifyVeilWebhook(
  env: VeilBindings,
  rawBody: string,
  signature: string,
) {
  const generic = Object.keys(configuredConnectionsCustodyProviders(env));
  const app = configuredGitHubAppIntegration(env);
  if (generic.length === 0 && app === undefined)
    throw new VeilError("github_not_configured");
  const decoded = Schema.decodeUnknownExit(
    Schema.fromJsonString(
      Schema.Struct({
        providerConfigKey: Schema.NonEmptyString,
      }),
    ),
  )(rawBody);
  if (Exit.isFailure(decoded)) throw new VeilError("invalid_completion");
  const key = decoded.value.providerConfigKey;
  const profile = generic.includes(key)
    ? ("connections" as const)
    : key === app
      ? ("computer-git" as const)
      : undefined;
  if (profile === undefined) throw new VeilError("invalid_completion");
  return {
    profile,
    ownerId: await verifiedConnectionOwner(env, rawBody, signature),
  };
}

/** The signed sign-in names the Team that began it; only a verified body is believed. */
async function verifiedConnectionOwner(
  env: VeilBindings,
  rawBody: string,
  signature: string,
): Promise<string> {
  const custody = configuredConnectionsCustody(env);
  if (custody === undefined) throw new VeilError("unavailable");
  try {
    return (await custody.verifyCompletion(rawBody, signature)).ownerId;
  } catch (cause) {
    if (cause instanceof ConnectionsError)
      throw new VeilError(
        cause.code === "unsupported"
          ? "unsupported"
          : cause.code === "unavailable"
            ? "unavailable"
            : "invalid_completion",
        { cause },
      );
    throw cause;
  }
}

type OpenApiHostConfiguration = {
  -readonly [K in keyof OpenApiDoorOptions]: OpenApiDoorOptions[K];
};

export type OpenApiHostOptions = Readonly<{
  connect: PublicConnect;
  fetch: typeof fetch;
  store: OpenApiCredentialStore;
  networkPolicy?: OpenApiDoorOptions["networkPolicy"];
  previousCredentialKeys?: Readonly<Record<string, string>>;
  oauthProviders?: Readonly<Record<string, OpenApiOAuthProvider>>;
}>;

/** The keyring that seals OpenAPI credentials; only Gatekeeper reads the master key. */
export function openApiCredentialKeyring(
  env: VeilBindings,
  previous?: Readonly<Record<string, string>>,
): OpenApiCredentialKeyring | undefined {
  const key = env.OPENAPI_CREDENTIAL_MASTER_KEY;
  if (!key) return undefined;
  const id = env.OPENAPI_CREDENTIAL_KEY_ID ?? "primary";
  return { activeKeyId: id, keys: { ...previous, [id]: key } };
}

/** Gatekeeper owns the common opaque configuration for both runtime facades. */
function openApiHostConfiguration(
  env: VeilBindings,
  options: OpenApiHostOptions,
): OpenApiDoorOptions {
  const doorOptions: OpenApiHostConfiguration = {
    connect: options.connect,
    resolve: createDnsOverHttpsResolver(options.fetch),
    networkPolicy: options.networkPolicy ?? {},
  };
  if (options.oauthProviders)
    doorOptions.oauthProviders = options.oauthProviders;
  const keys = openApiCredentialKeyring(env, options.previousCredentialKeys);
  if (keys) doorOptions.custody = { keys, store: options.store };
  return doorOptions;
}

/** Anonymous calls need no secret; API-key/bearer calls require configured Veil custody. */
export function configuredOpenApiDoor(
  env: VeilBindings,
  options: OpenApiHostOptions,
) {
  return createOpenApiDoor(openApiHostConfiguration(env, options));
}

/** Owned composition retains canonical Effects; secrets are read only by Gatekeeper. */
export function configuredOpenApiEffects(
  env: VeilBindings,
  options: OpenApiHostOptions,
): OpenApiEffects {
  return createOpenApiEffects(openApiHostConfiguration(env, options));
}
