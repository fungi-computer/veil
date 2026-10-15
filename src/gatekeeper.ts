import {
  createOpenApiDoor,
  type OpenApiCredentialStore,
  type OpenApiOAuthProvider,
  type OpenApiDoorOptions,
} from "./openapi.js";
import { createOpenApiEffects, type OpenApiEffects } from "./openapi-effect.js";
import { createDnsOverHttpsResolver } from "./model-key-network.js";
import type { PublicConnect } from "./public-fetch.js";
import { createNangoCustodian } from "./nango.js";
import { createWebhookTriggerSecrets } from "./webhook-trigger-secrets.js";
import { createNangoGitCustodian } from "./nango-git.js";
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
    NANGO_GITHUB_INTEGRATION_ID?: string;
    NANGO_GITHUB_GIT_INTEGRATION_ID?: string;
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

export function configuredGitHubState(env: VeilBindings) {
  const metadataIntegrationId = env.NANGO_GITHUB_INTEGRATION_ID;
  const gitIntegrationId = env.NANGO_GITHUB_GIT_INTEGRATION_ID;
  if (
    !metadataIntegrationId ||
    !gitIntegrationId ||
    metadataIntegrationId === gitIntegrationId
  )
    return { github: "off" as const };
  return {
    github: "on" as const,
    metadataIntegrationId,
    gitIntegrationId,
  };
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

export function configuredVeilCustodian(env: VeilBindings) {
  const state = configuredGitHubState(env);
  if (state.github === "off") throw new VeilError("github_not_configured");
  return configuredCustodian(env, state.metadataIntegrationId);
}

/** Git Connect/cleanup and final egress use the same Git-profile integration.
 * No metadata Connection locator is translated into this profile. Veil confines
 * the issued Connect document to the configured public Connect URLs. */
export function configuredComputerGitCustodian(env: VeilBindings) {
  const state = configuredGitHubState(env);
  if (state.github === "off") throw new VeilError("github_not_configured");
  const custody = configuredCustodian(env, state.gitIntegrationId);
  if (!env.NANGO_SERVER_URL || !env.NANGO_API_KEY)
    throw new VeilError("unavailable");
  try {
    const git = createNangoGitCustodian({
      serverUrl: env.NANGO_SERVER_URL,
      apiKey: env.NANGO_API_KEY,
      integrationId: state.gitIntegrationId,
    });
    return {
      integrationId: state.gitIntegrationId,
      openSession: custody.openSession,
      verifyCompletion: custody.verifyCompletion,
      verifyWebhook: custody.verifyWebhook,
      findCompletion: custody.findCompletion,
      deleteConnection: custody.deleteConnection,
      readGit: git.readGit.bind(git),
    };
  } catch {
    throw new VeilError("unavailable");
  }
}

/** The decoded key selects one of the two configured profiles only. The
 * selected maintained custodian still verifies the original signed body. */
export async function verifyVeilWebhook(
  env: VeilBindings,
  rawBody: string,
  signature: string,
) {
  const state = configuredGitHubState(env);
  if (state.github === "off") throw new VeilError("github_not_configured");
  const decoded = Schema.decodeUnknownExit(
    Schema.fromJsonString(
      Schema.Struct({
        providerConfigKey: Schema.NonEmptyString,
      }),
    ),
  )(rawBody);
  if (Exit.isFailure(decoded)) throw new VeilError("invalid_completion");
  if (decoded.value.providerConfigKey === state.gitIntegrationId) {
    return {
      profile: "computer-git" as const,
      ...(await configuredComputerGitCustodian(env).verifyWebhook(
        rawBody,
        signature,
      )),
    };
  }
  if (decoded.value.providerConfigKey === state.metadataIntegrationId) {
    return {
      profile: "agent-metadata" as const,
      ...(await configuredVeilCustodian(env).verifyWebhook(rawBody, signature)),
    };
  }
  throw new VeilError("invalid_completion");
}

function configuredCustodian(
  env: VeilBindings,
  integrationId: string | undefined,
) {
  if (
    !env.NANGO_SERVER_URL ||
    !env.NANGO_API_KEY ||
    !env.NANGO_WEBHOOK_SIGNING_KEY ||
    !env.NANGO_CONNECT_BASE_URL ||
    !env.NANGO_PUBLIC_API_URL ||
    !integrationId
  )
    throw new VeilError("unavailable");
  try {
    return createNangoCustodian({
      serverUrl: env.NANGO_SERVER_URL,
      apiKey: env.NANGO_API_KEY,
      webhookSigningKey: env.NANGO_WEBHOOK_SIGNING_KEY,
      integrationId,
      connectBaseUrl: env.NANGO_CONNECT_BASE_URL,
      publicApiUrl: env.NANGO_PUBLIC_API_URL,
    });
  } catch {
    throw new VeilError("unavailable");
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
  if (env.OPENAPI_CREDENTIAL_MASTER_KEY)
    doorOptions.custody = {
      keys: {
        activeKeyId: env.OPENAPI_CREDENTIAL_KEY_ID ?? "primary",
        keys: {
          ...options.previousCredentialKeys,
          [env.OPENAPI_CREDENTIAL_KEY_ID ?? "primary"]:
            env.OPENAPI_CREDENTIAL_MASTER_KEY,
        },
      },
      store: options.store,
    };
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
