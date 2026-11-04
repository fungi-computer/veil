import type {
  AuthorizationServerMetadata,
  FetchLike,
} from "@modelcontextprotocol/client";
import { ConnectionsError, type StaticOAuthProvider } from "./contract.js";
import type { OAuthBundle, OAuthClient } from "./oauth.js";

const metadataOf = (
  provider: StaticOAuthProvider,
): AuthorizationServerMetadata => ({
  issuer: provider.issuer,
  authorization_endpoint: provider.authorizationEndpoint,
  token_endpoint: provider.tokenEndpoint,
  response_types_supported: ["code"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: [
    provider.client.client_secret === undefined ? "none" : "client_secret_post",
  ],
});
const clientOf = (client: OAuthClient) =>
  client.client_secret === undefined
    ? { client_id: client.client_id }
    : { client_id: client.client_id, client_secret: client.client_secret };

/** PKCE redirect for an operator-registered provider. */
export async function startStaticAuthorization(input: {
  providerId: string;
  provider: StaticOAuthProvider;
  scope: string | undefined;
  callbackUrl: string;
  state: string;
}): Promise<{ authorizeUrl: string; bundle: OAuthBundle }> {
  const sdk = await import("@modelcontextprotocol/client");
  const scope = input.scope ?? input.provider.scope;
  const request: Parameters<typeof sdk.startAuthorization>[1] = {
    metadata: metadataOf(input.provider),
    clientInformation: clientOf(input.provider.client),
    redirectUrl: input.callbackUrl,
    state: input.state,
  };
  if (scope !== undefined) request.scope = scope;
  const started = await sdk.startAuthorization(input.provider.issuer, request);
  return {
    authorizeUrl: started.authorizationUrl.href,
    bundle: {
      authorizationServerUrl: input.provider.issuer,
      provider: input.providerId,
      client: input.provider.client,
      codeVerifier: started.codeVerifier,
      resource: undefined,
      tokens: undefined,
    },
  };
}

/** Redeem the code; the SDK validates `iss` against the provider's issuer. */
export async function finishStaticAuthorization(input: {
  provider: StaticOAuthProvider;
  bundle: OAuthBundle;
  callbackUrl: string;
  code: string;
  iss: string | undefined;
  now: number;
  fetch: FetchLike;
}): Promise<OAuthBundle> {
  const { bundle } = input;
  if (bundle.codeVerifier === undefined) throw new ConnectionsError("denied");
  const sdk = await import("@modelcontextprotocol/client");
  const request: Parameters<typeof sdk.exchangeAuthorization>[1] = {
    metadata: metadataOf(input.provider),
    clientInformation: clientOf(input.provider.client),
    authorizationCode: input.code,
    codeVerifier: bundle.codeVerifier,
    redirectUri: input.callbackUrl,
    fetchFn: input.fetch,
  };
  if (input.iss !== undefined) request.iss = input.iss;
  const tokens = await sdk.exchangeAuthorization(
    input.provider.issuer,
    request,
  );
  return {
    ...bundle,
    codeVerifier: undefined,
    tokens: {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      expires_in: tokens.expires_in,
      obtainedAt: input.now,
    },
  };
}

/** One refresh grant against the provider's own token endpoint. */
export async function refreshStaticTokens(input: {
  provider: StaticOAuthProvider;
  bundle: OAuthBundle;
  now: number;
  fetch: FetchLike;
}): Promise<OAuthBundle> {
  const held = input.bundle.tokens?.refresh_token;
  if (held === undefined) throw new ConnectionsError("reconnect_required");
  const sdk = await import("@modelcontextprotocol/client");
  try {
    const fresh = await sdk.refreshAuthorization(input.provider.issuer, {
      metadata: metadataOf(input.provider),
      clientInformation: clientOf(input.provider.client),
      refreshToken: held,
      fetchFn: input.fetch,
    });
    return {
      ...input.bundle,
      tokens: {
        access_token: fresh.access_token,
        refresh_token: fresh.refresh_token ?? held,
        expires_in: fresh.expires_in,
        obtainedAt: input.now,
      },
    };
  } catch (cause) {
    if (sdk.OAuthError.isInstance(cause) && cause.code === "invalid_grant")
      throw new ConnectionsError("reconnect_required", { cause });
    throw cause;
  }
}
