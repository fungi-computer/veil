import type {
  AuthOptions,
  FetchLike,
  OAuthClientMetadata,
  OAuthClientProvider,
} from "@modelcontextprotocol/client";
import * as Schema from "effect/Schema";
import { ConnectionsError } from "./contract.js";

/** Early-refresh margin so a token never expires mid-request. */
const skewMs = 30_000;

const tokensSchema = Schema.Struct({
  access_token: Schema.String,
  refresh_token: Schema.optional(Schema.String),
  /** Seconds the access token lives, as the authorization server said. */
  expires_in: Schema.optional(Schema.Number),
  obtainedAt: Schema.Number,
});
const clientSchema = Schema.Struct({
  client_id: Schema.String,
  client_secret: Schema.optional(Schema.String),
});
/**
 * Everything custody seals for one OAuth connection or attempt: the client,
 * the authorization server it was issued by, the PKCE verifier while an
 * attempt is pending, and the token set once it completes.
 */
const oauthBundleSchema = Schema.Struct({
  authorizationServerUrl: Schema.String,
  /** The operator-registered provider this was issued by, when there is one. */
  provider: Schema.optional(Schema.String),
  resource: Schema.optional(Schema.String),
  client: clientSchema,
  codeVerifier: Schema.optional(Schema.String),
  tokens: Schema.optional(tokensSchema),
});
export type OAuthBundle = typeof oauthBundleSchema.Type;
export type OAuthClient = typeof clientSchema.Type;
export const oauthClientJson = Schema.fromJsonString(clientSchema);
export const oauthBundleJson = Schema.fromJsonString(oauthBundleSchema);

/** Registered clients are reused for every connection to the same issuer. */
export type ClientRegistry = Readonly<{
  lookup: (issuer: string) => Promise<OAuthClient | undefined>;
  save: (issuer: string, client: OAuthClient) => Promise<void>;
}>;

export const tokenExpired = (bundle: OAuthBundle, now: number) => {
  const tokens = bundle.tokens;
  return (
    tokens?.expires_in !== undefined &&
    tokens.obtainedAt + tokens.expires_in * 1000 - skewMs <= now
  );
};

/** The SDK's exact-optional client shape. */
const clientInfo = (client: OAuthClient) =>
  client.client_secret === undefined
    ? { client_id: client.client_id }
    : { client_id: client.client_id, client_secret: client.client_secret };

/** What a flow remembered from the SDK's callbacks. */
type Captured = {
  authorizeUrl: URL | undefined;
  codeVerifier: string | undefined;
  client: OAuthClient | undefined;
  authorizationServerUrl: string | undefined;
  resource: string | undefined;
  tokens: typeof tokensSchema.Type | undefined;
};
const emptyCapture = (): Captured => ({
  authorizeUrl: undefined,
  codeVerifier: undefined,
  client: undefined,
  authorizationServerUrl: undefined,
  resource: undefined,
  tokens: undefined,
});

type FlowInput = {
  callbackUrl: string;
  scope: string | undefined;
  now: number;
  /** Authorization-code leg: replays what the redirect leg discovered. */
  resumed: { authorizationServerUrl: string; codeVerifier: string } | undefined;
  state: string | undefined;
  registry: ClientRegistry | undefined;
  /** Owner-supplied client: never registered and never shared. */
  own: OAuthClient | undefined;
};

function provider(flow: FlowInput, captured: Captured): OAuthClientProvider {
  const provided = flow.own ?? captured.client;
  const metadata = (): OAuthClientMetadata => {
    const base: OAuthClientMetadata = {
      redirect_uris: [flow.callbackUrl],
      client_name: "Fungi Oyster",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method:
        provided?.client_secret === undefined ? "none" : "client_secret_post",
    };
    if (flow.scope !== undefined) base.scope = flow.scope;
    return base;
  };
  const base: OAuthClientProvider = {
    redirectUrl: flow.callbackUrl,
    get clientMetadata() {
      return metadata();
    },
    clientInformation: async (ctx) => {
      const known =
        captured.client ??
        (ctx === undefined
          ? undefined
          : await flow.registry?.lookup(ctx.issuer));
      return known === undefined ? undefined : clientInfo(known);
    },
    saveClientInformation: async (info, ctx) => {
      const client: OAuthClient = {
        client_id: info.client_id,
        client_secret: info.client_secret,
      };
      captured.client = client;
      if (ctx !== undefined && flow.own === undefined)
        await flow.registry?.save(ctx.issuer, client);
    },
    tokens: () => undefined,
    saveTokens: (tokens) => {
      captured.tokens = {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        obtainedAt: flow.now,
      };
    },
    redirectToAuthorization: (url) => {
      captured.authorizeUrl = url;
    },
    saveCodeVerifier: (verifier) => {
      captured.codeVerifier = verifier;
    },
    codeVerifier: () => {
      const verifier = captured.codeVerifier ?? flow.resumed?.codeVerifier;
      if (verifier === undefined) throw new ConnectionsError("denied");
      return verifier;
    },
    saveDiscoveryState: (found) => {
      captured.authorizationServerUrl = found.authorizationServerUrl;
      captured.resource = found.resourceMetadata?.resource;
    },
    saveResourceUrl: (url) => {
      captured.resource = url;
    },
  };
  if (flow.state !== undefined) {
    const state = flow.state;
    base.state = () => state;
  }
  if (flow.resumed !== undefined) {
    const authorizationServerUrl = flow.resumed.authorizationServerUrl;
    base.discoveryState = () => ({ authorizationServerUrl });
  }
  return base;
}

function authOptions(
  serverUrl: string,
  fetchFn: FetchLike,
  extra: {
    scope?: string | undefined;
    code?: string;
    iss?: string | undefined;
  },
): AuthOptions {
  const options: AuthOptions = { serverUrl, fetchFn };
  if (extra.scope !== undefined) options.scope = extra.scope;
  if (extra.code !== undefined) options.authorizationCode = extra.code;
  if (extra.iss !== undefined) options.iss = extra.iss;
  return options;
}

export type OAuthStart = Readonly<{
  serverUrl: string;
  scope: string | undefined;
  client: OAuthClient | undefined;
  callbackUrl: string;
  state: string;
  registry: ClientRegistry;
  fetch: FetchLike;
}>;

/** Discovery, registration and PKCE through the SDK; returns the redirect and the sealed attempt. */
export async function startAuthorization(input: OAuthStart): Promise<{
  authorizeUrl: string;
  bundle: OAuthBundle;
}> {
  const captured = emptyCapture();
  captured.client = input.client;
  const flow = provider(
    {
      callbackUrl: input.callbackUrl,
      scope: input.scope,
      now: 0,
      resumed: undefined,
      state: input.state,
      registry: input.registry,
      own: input.client,
    },
    captured,
  );
  const sdk = await import("@modelcontextprotocol/client");
  const result = await sdk.auth(
    flow,
    authOptions(input.serverUrl, input.fetch, { scope: input.scope }),
  );
  if (
    result !== "REDIRECT" ||
    captured.authorizeUrl === undefined ||
    captured.client === undefined ||
    captured.codeVerifier === undefined ||
    captured.authorizationServerUrl === undefined
  )
    throw new ConnectionsError("invalid_response");
  return {
    authorizeUrl: captured.authorizeUrl.href,
    bundle: {
      authorizationServerUrl: captured.authorizationServerUrl,
      client: captured.client,
      codeVerifier: captured.codeVerifier,
      resource: captured.resource,
      tokens: undefined,
    },
  };
}

/** Redeem the code; the SDK validates `iss` and PKCE. The issuer must be the one the attempt began with. */
export async function finishAuthorization(input: {
  serverUrl: string;
  callbackUrl: string;
  bundle: OAuthBundle;
  code: string;
  iss: string | undefined;
  now: number;
  fetch: FetchLike;
}): Promise<OAuthBundle> {
  const { bundle } = input;
  if (bundle.codeVerifier === undefined) throw new ConnectionsError("denied");
  const captured = emptyCapture();
  captured.client = bundle.client;
  const flow = provider(
    {
      callbackUrl: input.callbackUrl,
      scope: undefined,
      now: input.now,
      resumed: {
        authorizationServerUrl: bundle.authorizationServerUrl,
        codeVerifier: bundle.codeVerifier,
      },
      state: undefined,
      registry: undefined,
      own: bundle.client,
    },
    captured,
  );
  const sdk = await import("@modelcontextprotocol/client");
  const result = await sdk.auth(
    flow,
    authOptions(input.serverUrl, input.fetch, {
      code: input.code,
      iss: input.iss,
    }),
  );
  if (
    result !== "AUTHORIZED" ||
    captured.tokens === undefined ||
    captured.authorizationServerUrl !== bundle.authorizationServerUrl
  )
    throw new ConnectionsError("denied");
  return {
    authorizationServerUrl: bundle.authorizationServerUrl,
    client: bundle.client,
    resource: captured.resource ?? bundle.resource,
    codeVerifier: undefined,
    tokens: captured.tokens,
  };
}

/**
 * One refresh grant. A rotated refresh token replaces the old one; the caller
 * persists the returned bundle before using the new access token.
 */
export async function refreshTokens(input: {
  bundle: OAuthBundle;
  now: number;
  fetch: FetchLike;
}): Promise<OAuthBundle> {
  const { bundle } = input;
  const held = bundle.tokens?.refresh_token;
  if (held === undefined) throw new ConnectionsError("reconnect_required");
  const sdk = await import("@modelcontextprotocol/client");
  try {
    const metadata = await sdk.discoverAuthorizationServerMetadata(
      bundle.authorizationServerUrl,
      { fetchFn: input.fetch },
    );
    const options: Parameters<
      typeof import("@modelcontextprotocol/client").refreshAuthorization
    >[1] = {
      clientInformation: clientInfo(bundle.client),
      refreshToken: held,
      fetchFn: input.fetch,
    };
    if (metadata !== undefined) options.metadata = metadata;
    if (bundle.resource !== undefined)
      options.resource = new URL(bundle.resource);
    const fresh = await sdk.refreshAuthorization(
      bundle.authorizationServerUrl,
      options,
    );
    return {
      ...bundle,
      tokens: {
        access_token: fresh.access_token,
        refresh_token: fresh.refresh_token ?? held,
        expires_in: fresh.expires_in,
        obtainedAt: input.now,
      },
    };
  } catch (cause) {
    // The server no longer honours the grant: only a new authorization helps.
    if (sdk.OAuthError.isInstance(cause) && cause.code === "invalid_grant")
      throw new ConnectionsError("reconnect_required", { cause });
    throw cause;
  }
}
