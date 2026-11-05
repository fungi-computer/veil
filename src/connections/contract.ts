import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import type { PublicEgressPolicy } from "../public-egress-policy.js";

export type ConnectionsRefusal =
  | "invalid_input"
  | "denied"
  | "revoked"
  | "conflict"
  | "unsupported"
  | "too_large"
  | "reconnect_required"
  | "pending"
  | "invalid_response"
  /** The provider's rate limit refused the request; retry later. */
  | "rate_limited"
  | "unavailable";

/** Fixed codes only: upstream bodies, URLs and credential bytes never enter errors. */
export class ConnectionsError extends Error {
  override readonly name = "ConnectionsError";
  constructor(
    readonly code: ConnectionsRefusal,
    options?: ErrorOptions,
  ) {
    super(code, options);
  }
}

/** How long a sign-in attempt stays open before it expires. */
export const attemptTtlMs = 10 * 60 * 1000;

export const identifier = Schema.String.pipe(
  Schema.check(Schema.isPattern(/^[A-Za-z0-9_.:-]{1,128}$/u)),
);
const headerName = Schema.String.pipe(
  Schema.check(Schema.isPattern(/^[A-Za-z0-9-]{1,64}$/u)),
);
const queryName = Schema.String.pipe(
  Schema.check(Schema.isPattern(/^[A-Za-z0-9_.-]{1,64}$/u)),
);
const version = Schema.Number.pipe(
  Schema.check(Schema.isInt(), Schema.isGreaterThanOrEqualTo(1)),
);

const placementSchema = Schema.Union([
  Schema.Literal("bearer"),
  Schema.Struct({ header: headerName }),
  Schema.Struct({ query: queryName }),
]);
export type Placement = typeof placementSchema.Type;

/**
 * How the final request is authorized. For `oauth` the owner may bring its own
 * client (`clientId`, with the client secret as the draft's `secret`); without
 * one the server's dynamic registration is used.
 */
export const credentialSchema = Schema.Union([
  Schema.Struct({ kind: Schema.Literal("none") }),
  Schema.Struct({ kind: Schema.Literal("static"), placement: placementSchema }),
  Schema.Struct({
    kind: Schema.Literal("oauth"),
    scope: Schema.optional(Schema.String),
    clientId: Schema.optional(Schema.String),
    /** An operator-registered REST provider; absent for an MCP server's own sign-in. */
    provider: Schema.optional(Schema.String),
  }),
]);
export type Credential = typeof credentialSchema.Type;

/** What the Agent can call. The OpenAPI table is decoded by Forage before it is stored. */
const surfaceDraftSchema = Schema.Union([
  Schema.Struct({ kind: Schema.Literal("mcp"), url: Schema.String }),
  Schema.Struct({
    kind: Schema.Literal("openapi"),
    baseUrl: Schema.String,
    table: Schema.Array(Schema.Unknown),
  }),
]);
export type SurfaceView =
  | Readonly<{ kind: "mcp"; url: string }>
  | Readonly<{
      kind: "openapi";
      baseUrl: string;
      table: readonly unknown[];
      /** Digest of the decoded operation table. */
      digest: string;
    }>;

export const toolsSchema = Schema.Union([
  Schema.Literal("all"),
  /** OpenAPI only: every operation whose stored effect is `read`. */
  Schema.Struct({ effect: Schema.Literal("read") }),
  Schema.Array(
    Schema.String.pipe(
      Schema.check(Schema.isMinLength(1), Schema.isMaxLength(256)),
    ),
  ).pipe(Schema.check(Schema.isMaxLength(256))),
]);
export type Tools = typeof toolsSchema.Type;

export const draftSchema = Schema.Struct({
  /** Idempotency key: a replay with the same request returns the same connection. */
  requestId: identifier,
  name: Schema.String.pipe(
    Schema.check(Schema.isMinLength(1), Schema.isMaxLength(128)),
  ),
  /** Display text for owners; defaults to the name. */
  label: Schema.optional(
    Schema.String.pipe(
      Schema.check(Schema.isMinLength(1), Schema.isMaxLength(128)),
    ),
  ),
  surface: surfaceDraftSchema,
  credential: credentialSchema,
  secret: Schema.optional(
    Schema.String.pipe(
      Schema.check(Schema.isPattern(/^[\x21-\x7e]{1,16384}$/u)),
    ),
  ),
});
export type ConnectionDraft = typeof draftSchema.Type;
export const grantInputSchema = Schema.Struct({
  connectionId: identifier,
  agentId: identifier,
  tools: toolsSchema,
});
export type GrantInput = typeof grantInputSchema.Type;
/** The authorization server's redirect back to the owner. */
export const completeInputSchema = Schema.Struct({
  state: Schema.String.pipe(Schema.check(Schema.isMaxLength(512))),
  code: Schema.String.pipe(Schema.check(Schema.isMaxLength(4096))),
  iss: Schema.optional(
    Schema.String.pipe(Schema.check(Schema.isMaxLength(2048))),
  ),
});
export type CompleteInput = typeof completeInputSchema.Type;
/** Owner edits to a live connection, guarded by the version the owner last saw. */
export const updateInputSchema = Schema.Struct({
  requestId: identifier,
  connectionId: identifier,
  expectedVersion: version,
  label: Schema.optional(
    Schema.String.pipe(
      Schema.check(Schema.isMinLength(1), Schema.isMaxLength(128)),
    ),
  ),
  name: Schema.optional(
    Schema.String.pipe(
      Schema.check(Schema.isMinLength(1), Schema.isMaxLength(128)),
    ),
  ),
  /** Replacement OpenAPI operation table, decoded by Forage. */
  table: Schema.optional(Schema.Array(Schema.Unknown)),
  baseUrl: Schema.optional(Schema.String),
  /** Credential swap; `none` and `static` only. */
  credential: Schema.optional(credentialSchema),
  secret: Schema.optional(
    Schema.String.pipe(
      Schema.check(Schema.isPattern(/^[\x21-\x7e]{1,16384}$/u)),
    ),
  ),
});
export type UpdateInput = typeof updateInputSchema.Type;
/** One typed OpenAPI operation call. */
export const callInputSchema = Schema.Struct({
  operation: Schema.String.pipe(Schema.check(Schema.isMaxLength(256))),
  input: Schema.Unknown,
});
export type CallInput = typeof callInputSchema.Type;
export const egressRefSchema = Schema.Struct({
  connectionId: identifier,
  grantVersion: version,
});
export type EgressRef = typeof egressRefSchema.Type;

/** Where custody finds one connection; carries no secret. */
export type CustodyAddress = Readonly<{
  ownerId: string;
  connectionId: string;
  credential: Credential;
}>;
/**
 * Owner-side credential custody. `sealed` stores ciphertext, `nango` a locator.
 * Only `inject` ever opens a credential, and it sends the request itself.
 */
export type CustodyAdapter = Readonly<{
  put: (
    address: CustodyAddress,
    secret: string,
  ) => Effect.Effect<string, ConnectionsError>;
  inject: (
    address: CustodyAddress,
    locator: string,
    request: Request,
  ) => Effect.Effect<Response, ConnectionsError>;
  remove: (
    address: CustodyAddress,
    locator: string,
  ) => Effect.Effect<"deleted" | "absent", ConnectionsError>;
  /**
   * Release a sealed OAuth bundle to the owner's connections core, which runs
   * the authorization flow and refreshes tokens. Never reaches an Agent.
   */
  open?: (
    address: CustodyAddress,
    locator: string,
  ) => Effect.Effect<string, ConnectionsError>;
  /**
   * A custodian that runs the authorization itself (Nango's Connect) returns
   * the page to send the owner to; it settles through a signed completion
   * (`complete`) carrying the `state` given here, not through our callback.
   */
  /**
   * Ask a custodian that ran an authorization whether it finished, when its
   * signed completion never arrived. Only an exact match of the attempt's
   * state, actor and integration counts; two matches are ambiguous.
   */
  find?: (
    address: CustodyAddress,
    attempt: Readonly<{ state: string; actor: string; integrationId: string }>,
  ) => Effect.Effect<CustodyLookup, ConnectionsError>;
  connect?: (
    address: CustodyAddress,
    attempt: Readonly<{ state: string; actor: string; integrationId: string }>,
  ) => Effect.Effect<
    Readonly<{ connectUrl: string; expiresAt: number }>,
    ConnectionsError
  >;
}>;
export type CustodyLookup =
  | Readonly<{ status: "unresolved" }>
  | Readonly<{ status: "ambiguous" }>
  | Readonly<{ status: "found"; locator: string }>;
/**
 * What a custodian proves after it ran an authorization: the attempt's state
 * and where it keeps the credential. The host verifies the custodian's
 * signature before it builds one.
 */
export type CustodyCompletion = Readonly<{
  state: string;
  locator: string;
  /** Who the custodian says signed in; it must be who began the attempt. */
  principalId: string;
  /** The integration the custodian ran it through; it must be the one the attempt began with. */
  integrationId: string;
}>;

export type SqlValue = string | number | null;
/** The owner's SQLite in Cloudflare `ctx.storage` shape. */
export type SqlStore = Readonly<{
  sql: Readonly<{
    exec: (
      statement: string,
      ...bindings: SqlValue[]
    ) => Readonly<{ toArray: () => readonly unknown[] }>;
  }>;
  transactionSync: <A>(operation: () => A) => A;
}>;

/**
 * A REST provider the operator registered an app with. Such providers publish
 * no metadata the SDK can discover, and many require a pre-registered client,
 * so the host names the endpoints and holds the client. Only the operator's
 * configuration reaches this type; neither an Agent nor an owner supplies one.
 */
export type StaticOAuthProvider = Readonly<{
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  /** Scopes requested when the owner names none. */
  scope?: string;
  client: { client_id: string; client_secret?: string | undefined };
  /** The https origins this provider's API serves; its token goes nowhere else. */
  apiOrigins: readonly string[];
}>;

/**
 * An integration a custodian runs the sign-in for, as the operator declared
 * it: the https origins its credential may reach. The custodian attaches the
 * credential to whatever origin it is handed, so the core pins it here.
 */
export type CustodyProvider = Readonly<{ apiOrigins: readonly string[] }>;

export type ConnectionsOptions = Readonly<{
  ownerId: string;
  store: SqlStore;
  custody: CustodyAdapter;
  /** Host authority read: may this actor manage connections, or still stand as a grantor? */
  authorize: (actorId: string, purpose: "manage" | "grantor") => boolean;
  /**
   * Asked right before every send, with the grantor who stands behind the
   * grant. The host keeps its own live recheck here (membership, write
   * rights); the core never learns what the host's policy is.
   */
  check?: (
    grantor: string,
    grant: Readonly<{ agentId: string; connectionId: string; tools: Tools }>,
    operation: Readonly<{
      name: string;
      effect: "read" | "write" | null;
    }> | null,
  ) => Promise<boolean>;
  egressPolicy?: PublicEgressPolicy;
  /**
   * Needed only for `oauth` connections: where the authorization server sends
   * the owner back, and the checked public transport for discovery, token and
   * refresh requests. Custody must also implement `open`.
   */
  oauth?:
    | Readonly<{
        callbackUrl: string;
        fetch: (request: Request) => Promise<Response>;
        /** REST providers the operator registered an app with, by id. */
        providers?: Readonly<Record<string, StaticOAuthProvider>>;
      }>
    | undefined;
  /**
   * Integrations the custodian signs in through, by id. An OAuth provider id
   * that is neither here nor in `oauth.providers` is refused.
   */
  custodyProviders?: Readonly<Record<string, CustodyProvider>> | undefined;
  clock: () => number;
  ids: () => string;
}>;

/** Secret-free, versioned, and safe to hand to an Agent. */
export type ConnectionProjection = Readonly<{
  revision: number;
  connections: readonly Readonly<{
    connectionId: string;
    name: string;
    surface: SurfaceView;
    tools: Tools;
    /** Bumped by every `update`. */
    version: number;
    authorityVersion: number;
    grantVersion: number;
  }>[];
}>;
export type ConnectionView = Readonly<{
  connectionId: string;
  name: string;
  label: string;
  surface: Readonly<{
    kind: "mcp" | "openapi";
    origin: string;
    url: string;
    digest: string | null;
  }>;
  credentialKind: Credential["kind"];
  /** How the secret is placed; the secret itself never appears. */
  credential: Credential;
  state: "pending" | "active" | "reconnect_required" | "revoked";
  version: number;
  authorityVersion: number;
  grants: readonly Readonly<{
    agentId: string;
    tools: Tools;
    version: number;
    grantor: string;
  }>[];
}>;

/** The Agent's narrowed capability: only the owner opens the credential. */
export type NarrowFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;
