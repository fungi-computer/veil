import * as Schema from "effect/Schema";
import * as Exit from "effect/Exit";
import {
  VeilError,
  type CredentialCustodian,
  type VerifiedCompletion,
  type VerifiedWebhook,
} from "./index.js";

const text = Schema.NonEmptyString;
const tagsSchema = Schema.Struct({
  veil_team_id: text,
  veil_attempt_id: text,
  veil_principal_id: text,
});
const sessionSchema = Schema.Struct({
  data: Schema.Struct({
    token: text,
    connect_link: text,
    expires_at: Schema.DateFromString,
  }),
});
const webhookEnvelopeSchema = Schema.Struct({
  type: text,
  operation: Schema.optional(text),
});
/** Nango auth webhook fields shared by creation and refresh notifications. */
const authWebhookSchema = Schema.Struct({
  type: Schema.Literal("auth"),
  operation: Schema.Literals(["creation", "refresh"]),
  success: Schema.Boolean,
  connectionId: text,
  providerConfigKey: text,
  tags: tagsSchema,
  endUser: Schema.Struct({ endUserId: text, organizationId: text }),
});
/** GitHub's own unauthorized body, as relayed verbatim by the Nango proxy.
 * Nango's own errors use an `error` envelope and remain unavailable. */
const providerUnauthorizedSchema = Schema.Struct({
  message: text,
  documentation_url: text,
});
const connectionSchema = Schema.Struct({
  connection_id: text,
  provider_config_key: text,
  tags: tagsSchema,
  end_user: Schema.Struct({
    id: text,
    organization: Schema.Struct({ id: text }),
  }),
});
const connectionsSchema = Schema.Struct({
  connections: Schema.Array(connectionSchema),
});
const deletedSchema = Schema.Struct({ success: Schema.Literal(true) });
const absentSchema = Schema.Struct({
  error: Schema.Struct({ code: Schema.Literal("unknown_connection") }),
});

/** Trusted host configuration; never supplied by a model or Connect browser.
 * The public Connect document and API URLs are independent of the internal
 * serverUrl the Hub uses for custody. */
export type NangoCustodianOptions = Readonly<{
  serverUrl: string;
  apiKey: string;
  webhookSigningKey: string;
  integrationId: string;
  connectBaseUrl: string;
  publicApiUrl: string;
  /** Deadline for one custodian request and its body; a miss is `unavailable`. */
  requestTimeoutMs?: number;
}>;

/** A custodian that stops answering is an outage, retried later, never a dead credential. */
const defaultRequestTimeoutMs = 10_000;

function publicUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new VeilError("invalid_input");
  }
  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    throw new VeilError("invalid_input");
  return url;
}

/** The Connect document handed to browsers: Nango's issued link, confined to
 * the configured Connect UI and pinned to the configured public API. */
function connectDocument(
  session: Readonly<{ token: string; connectUrl: string }>,
  base: URL,
  api: URL,
): string {
  let document: URL;
  try {
    document = new URL(session.connectUrl);
  } catch {
    throw new VeilError("invalid_response");
  }
  if (
    document.origin !== base.origin ||
    document.pathname !== base.pathname ||
    document.username ||
    document.password ||
    document.hash ||
    document.searchParams.get("session_token") !== session.token
  )
    throw new VeilError("invalid_response");
  document.searchParams.set("apiURL", api.href);
  return document.href;
}

/** Pinned Nango Connect/connection REST contract and maintained raw-body verifier. */
export function createNangoCustodian(
  options: NangoCustodianOptions,
): CredentialCustodian {
  let server: URL;
  try {
    server = new URL(options.serverUrl);
  } catch {
    throw new VeilError("invalid_input");
  }
  if (
    !options.apiKey ||
    !options.webhookSigningKey ||
    !options.integrationId ||
    server.username ||
    server.password ||
    server.search ||
    server.hash ||
    server.pathname !== "/" ||
    (server.protocol !== "https:" && server.protocol !== "http:")
  )
    throw new VeilError("invalid_input");
  const connectBase = publicUrl(options.connectBaseUrl);
  if (!connectBase.pathname.endsWith("/")) connectBase.pathname += "/";
  const publicApi = publicUrl(options.publicApiUrl);
  const decode = <A, I>(
    schema: Schema.Codec<A, I>,
    raw: string,
    code: "invalid_response" | "invalid_completion" = "invalid_response",
  ): A => {
    try {
      return Schema.decodeUnknownSync(Schema.fromJsonString(schema))(raw);
    } catch {
      throw new VeilError(code);
    }
  };
  const requestTimeoutMs = options.requestTimeoutMs ?? defaultRequestTimeoutMs;
  const request = async (
    path: string,
    signal: AbortSignal,
    init: RequestInit = {},
  ) => {
    try {
      signal.throwIfAborted();
      const headers = new Headers(init.headers);
      headers.set("Authorization", `Bearer ${options.apiKey}`);
      // The deadline also aborts the body stream that `body` reads next.
      return await fetch(new URL(path, server), {
        ...init,
        headers,
        signal: AbortSignal.any([
          signal,
          AbortSignal.timeout(requestTimeoutMs),
        ]),
        redirect: "manual",
      });
    } catch {
      throw new VeilError(signal.aborted ? "cancelled" : "unavailable");
    }
  };
  const body = async (response: Response, signal: AbortSignal) => {
    try {
      return await response.text();
    } catch {
      throw new VeilError(signal.aborted ? "cancelled" : "unavailable");
    }
  };
  const requireSuccess = (response: Response) => {
    if (!response.ok) throw new VeilError("unavailable");
  };
  const tags = (teamId: string, attemptId: string, principalId: string) => ({
    veil_team_id: teamId,
    veil_attempt_id: attemptId,
    veil_principal_id: principalId,
  });
  const completion = (
    row: Schema.Schema.Type<typeof tagsSchema>,
    integrationId: string,
    locator: string,
  ): VerifiedCompletion => ({
    teamId: row.veil_team_id,
    attemptId: row.veil_attempt_id,
    principalId: row.veil_principal_id,
    integrationId,
    locator,
  });
  /**
   * Maintained HMAC over the raw body first; only then decode the operation.
   * The Nango SDK (and its HTTP client) loads with the first webhook rather
   * than with every Worker that hosts a custodian.
   */
  const verifyWebhook = (
    rawBody: string,
    signature: string,
  ): Promise<VerifiedWebhook> =>
    import("@nangohq/node").then(({ Nango }) => {
      const verifier = new Nango({
        host: server.origin,
        apiKey: options.apiKey,
        webhookSigningKey: options.webhookSigningKey,
      });
      if (
        !verifier.verifyIncomingWebhookRequest(rawBody, {
          "X-Nango-Hmac-Sha256": signature,
        })
      )
        throw new VeilError("invalid_completion");
      const envelope = decode(
        webhookEnvelopeSchema,
        rawBody,
        "invalid_completion",
      );
      if (
        envelope.type !== "auth" ||
        (envelope.operation !== "creation" && envelope.operation !== "refresh")
      )
        throw new VeilError("unsupported");
      const row = decode(authWebhookSchema, rawBody, "invalid_completion");
      // Handled: a successful creation, or a failed credential refresh.
      if (row.success !== (row.operation === "creation"))
        throw new VeilError("unsupported");
      if (
        row.providerConfigKey !== options.integrationId ||
        row.endUser.endUserId !== row.tags.veil_principal_id ||
        row.endUser.organizationId !== row.tags.veil_team_id
      )
        throw new VeilError("invalid_completion");
      return {
        operation: row.operation === "creation" ? "creation" : "refresh_failed",
        completion: completion(
          row.tags,
          row.providerConfigKey,
          row.connectionId,
        ),
      };
    });
  return {
    async openSession(input, signal) {
      if (input.integrationId !== options.integrationId)
        throw new VeilError("denied");
      const response = await request("/connect/sessions", signal, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          allowed_integrations: [options.integrationId],
          end_user: { id: input.principalId },
          organization: { id: input.teamId },
          tags: tags(input.teamId, input.attemptId, input.principalId),
        }),
      });
      requireSuccess(response);
      const { data } = decode(sessionSchema, await body(response, signal));
      return {
        token: data.token,
        connectUrl: connectDocument(
          { token: data.token, connectUrl: data.connect_link },
          connectBase,
          publicApi,
        ),
        expiresAt: data.expires_at.getTime(),
      };
    },
    verifyWebhook,
    async verifyCompletion(rawBody, signature) {
      const event = await verifyWebhook(rawBody, signature);
      if (event.operation !== "creation") throw new VeilError("unsupported");
      return event.completion;
    },
    async findCompletion(attempt, signal) {
      if (attempt.integrationId !== options.integrationId)
        throw new VeilError("denied");
      const expected = tags(
        attempt.teamId,
        attempt.attemptId,
        attempt.actorUserId,
      );
      const query = new URLSearchParams({
        integrationId: options.integrationId,
        endUserId: attempt.actorUserId,
        endUserOrganizationId: attempt.teamId,
        limit: "2",
        page: "0",
      });
      for (const [key, value] of Object.entries(expected))
        query.set(`tags[${key}]`, value);
      const response = await request(
        `/connections?${query.toString()}`,
        signal,
      );
      requireSuccess(response);
      const { connections } = decode(
        connectionsSchema,
        await body(response, signal),
      );
      // Selected server filters before LIMIT; two rows are sufficient to prove ambiguity.
      for (const row of connections) {
        if (
          row.provider_config_key !== options.integrationId ||
          row.end_user.id !== attempt.actorUserId ||
          row.end_user.organization.id !== attempt.teamId ||
          row.tags.veil_team_id !== attempt.teamId ||
          row.tags.veil_attempt_id !== attempt.attemptId ||
          row.tags.veil_principal_id !== attempt.actorUserId
        )
          throw new VeilError("invalid_response");
      }
      if (connections.length === 0) return { status: "unresolved" };
      if (connections.length !== 1) return { status: "ambiguous" };
      const row = connections[0];
      if (!row) throw new VeilError("invalid_response");
      return {
        status: "verified",
        completion: completion(
          row.tags,
          row.provider_config_key,
          row.connection_id,
        ),
      };
    },
    async deleteConnection(locator, signal) {
      const query = new URLSearchParams({
        provider_config_key: options.integrationId,
      });
      const response = await request(
        `/connections/${encodeURIComponent(locator)}?${query.toString()}`,
        signal,
        { method: "DELETE" },
      );
      const raw = await body(response, signal);
      // This pinned public endpoint reports absent as HTTP400, not a generic404.
      if (response.status === 400) {
        decode(absentSchema, raw);
        return "absent";
      }
      requireSuccess(response);
      decode(deletedSchema, raw);
      return "deleted";
    },
    async readRepository(access, signal) {
      // WHATWG URL normalizes dot segments, including percent-encoded dots.
      if (
        [access.repository.owner, access.repository.name].some(
          (part) => part === "." || part === "..",
        )
      )
        throw new VeilError("invalid_input");
      const path = `/proxy/repos/${encodeURIComponent(access.repository.owner)}/${encodeURIComponent(access.repository.name)}`;
      const response = await request(path, signal, {
        headers: {
          "Connection-Id": access.locator,
          "Provider-Config-Key": options.integrationId,
        },
      });
      if (response.status === 401) {
        const evidence = Schema.decodeUnknownExit(
          Schema.fromJsonString(providerUnauthorizedSchema),
        )(await body(response, signal));
        throw new VeilError(
          Exit.isSuccess(evidence) ? "reconnect_required" : "unavailable",
        );
      }
      requireSuccess(response);
      return await body(response, signal);
    },
  };
}
