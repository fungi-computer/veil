import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import {
  authWebhookSchema,
  connectDocument,
  publicUrl,
  sessionSchema,
  webhookEnvelopeSchema,
} from "../nango.js";
import { createNangoCustodyHttp } from "../nango-custody-http.js";
import { VeilError } from "../index.js";
import {
  ConnectionsError,
  type CustodyAdapter,
  type CustodyCompletion,
} from "./contract.js";

/**
 * Trusted host configuration. `staticIntegrationId` is an API-key integration
 * whose proxy attaches the credential an owner pasted; OAuth connections name
 * their own integration when they begin. The Connect document and API URLs
 * are public and independent of the internal `serverUrl`.
 */
export type NangoCustodyOptions = Readonly<{
  serverUrl: string;
  apiKey: string;
  webhookSigningKey: string;
  staticIntegrationId: string;
  connectBaseUrl: string;
  publicApiUrl: string;
  requestTimeoutMs?: number;
}>;

const defaultTimeoutMs = 10_000;
const decode = <A, I>(schema: Schema.Codec<A, I>, raw: string): A => {
  try {
    return Schema.decodeUnknownSync(Schema.fromJsonString(schema))(raw);
  } catch (cause) {
    throw new ConnectionsError("invalid_response", { cause });
  }
};
/** Nango says no body of ours is wrong; any failure to speak with it is an outage. */
const outage = (cause: unknown) =>
  cause instanceof ConnectionsError
    ? cause
    : cause instanceof VeilError
      ? new ConnectionsError(
          cause.code === "invalid_response"
            ? "invalid_response"
            : "unavailable",
          { cause },
        )
      : new ConnectionsError("unavailable", { cause });
const attempt = <A>(body: () => Promise<A>) =>
  Effect.tryPromise({ try: body, catch: outage });

/** A custodian that also verifies its signed completion for the host. */
export type ConnectionsCustodian = CustodyAdapter &
  Readonly<{
    verifyCompletion: (
      rawBody: string,
      signature: string,
    ) => Promise<CustodyCompletion & Readonly<{ ownerId: string }>>;
  }>;

/**
 * Nango as a `CustodyAdapter`: `put` imports an API-key connection, `inject`
 * sends through Nango's proxy (which attaches and refreshes the credential),
 * `remove` deletes the connection, and `connect` opens a Connect session for
 * an authorization Nango runs. `verifyCompletion` turns its signed webhook
 * into a `CustodyCompletion` for the core.
 */
export function createNangoCustody(
  options: NangoCustodyOptions,
): ConnectionsCustodian {
  const http = createNangoCustodyHttp(options);
  const connectBase = publicUrl(options.connectBaseUrl);
  if (!connectBase.pathname.endsWith("/")) connectBase.pathname += "/";
  const publicApi = publicUrl(options.publicApiUrl);
  const timeoutMs = options.requestTimeoutMs ?? defaultTimeoutMs;
  const signal = () => AbortSignal.timeout(timeoutMs);
  return {
    put: (address, secret) =>
      attempt(async () => {
        if (address.credential.kind !== "static")
          throw new ConnectionsError("unsupported");
        await http.importCredential(
          {
            integrationId: options.staticIntegrationId,
            locator: address.connectionId,
            teamId: address.ownerId,
            credential: secret,
          },
          signal(),
        );
        return address.connectionId;
      }),
    inject: (address, locator, request) =>
      attempt(async () => {
        const target = new URL(request.url);
        const headers = new Headers();
        for (const [name, value] of request.headers)
          headers.set(`Nango-Proxy-${name}`, value);
        const contentType = request.headers.get("content-type");
        if (contentType !== null) headers.set("Content-Type", contentType);
        headers.set(
          "Provider-Config-Key",
          address.credential.kind === "oauth" &&
            address.credential.provider !== undefined
            ? address.credential.provider
            : options.staticIntegrationId,
        );
        headers.set("Connection-Id", locator);
        headers.set("Base-Url-Override", target.origin);
        headers.set("Retries", "0");
        const response = await http.call(
          `/proxy${target.pathname}${target.search}`,
          request.signal,
          {
            method: request.method,
            headers,
            body: request.method === "GET" ? null : request.body,
            // Native Node fetch requires this for a stream; Workers accepts it.
            duplex: "half",
          },
        );
        // Nango's own refusal of a connection it no longer holds is not the provider's answer.
        if (response.status === 404) {
          await response.body?.cancel();
          throw new ConnectionsError("reconnect_required");
        }
        return response;
      }),
    remove: (address, locator) =>
      attempt(() =>
        http.removeConnection(
          locator,
          address.credential.kind === "oauth" &&
            address.credential.provider !== undefined
            ? address.credential.provider
            : options.staticIntegrationId,
          signal(),
        ),
      ),
    connect: (address, session) =>
      attempt(async () => {
        const response = await http.call("/connect/sessions", signal(), {
          method: "POST",
          headers: new Headers({ "Content-Type": "application/json" }),
          body: JSON.stringify({
            allowed_integrations: [session.integrationId],
            end_user: { id: session.actor },
            organization: { id: address.ownerId },
            tags: {
              veil_team_id: address.ownerId,
              veil_attempt_id: session.state,
              veil_principal_id: session.actor,
            },
          }),
        });
        if (!response.ok) throw new ConnectionsError("unavailable");
        const { data } = decode(sessionSchema, await response.text());
        return {
          connectUrl: connectDocument(
            { token: data.token, connectUrl: data.connect_link },
            connectBase,
            publicApi,
          ),
          expiresAt: data.expires_at.getTime(),
        };
      }),
    verifyCompletion: async (rawBody, signature) => {
      // Maintained HMAC over the raw body first; only then decode the event.
      const { Nango } = await import("@nangohq/node");
      const verifier = new Nango({
        host: new URL(options.serverUrl).origin,
        apiKey: options.apiKey,
        webhookSigningKey: options.webhookSigningKey,
      });
      if (
        !verifier.verifyIncomingWebhookRequest(rawBody, {
          "X-Nango-Hmac-Sha256": signature,
        })
      )
        throw new ConnectionsError("denied");
      const envelope = decode(webhookEnvelopeSchema, rawBody);
      if (envelope.type !== "auth" || envelope.operation !== "creation")
        throw new ConnectionsError("unsupported");
      const row = decode(authWebhookSchema, rawBody);
      if (
        !row.success ||
        row.endUser.endUserId !== row.tags.veil_principal_id ||
        row.endUser.organizationId !== row.tags.veil_team_id
      )
        throw new ConnectionsError("denied");
      return {
        ownerId: row.tags.veil_team_id,
        state: row.tags.veil_attempt_id,
        locator: row.connectionId,
        integrationId: row.providerConfigKey,
      };
    },
  };
}
