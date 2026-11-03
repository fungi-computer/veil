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
  | "invalid_response"
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

/** How the final request is authorized. OAuth joins this union in slice 3. */
export const credentialSchema = Schema.Union([
  Schema.Struct({ kind: Schema.Literal("none") }),
  Schema.Struct({ kind: Schema.Literal("static"), placement: placementSchema }),
]);
export type Credential = typeof credentialSchema.Type;

/** What the Agent can call. The OpenAPI table is decoded by Forage before it is stored. */
const surfaceDraftSchema = Schema.Union([
  Schema.Struct({ kind: Schema.Literal("mcp"), url: Schema.String }),
  Schema.Struct({
    kind: Schema.Literal("openapi"),
    baseUrl: Schema.String,
    table: Schema.Unknown,
  }),
]);
export type SurfaceView =
  | Readonly<{ kind: "mcp"; url: string }>
  | Readonly<{ kind: "openapi"; baseUrl: string; table: unknown }>;

export const toolsSchema = Schema.Union([
  Schema.Literal("all"),
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

export type ConnectionsOptions = Readonly<{
  ownerId: string;
  store: SqlStore;
  custody: CustodyAdapter;
  /** Host authority read: may this actor manage connections, or still stand as a grantor? */
  authorize: (actorId: string, purpose: "manage" | "grantor") => boolean;
  egressPolicy?: PublicEgressPolicy;
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
    authorityVersion: number;
    grantVersion: number;
  }>[];
}>;
export type ConnectionView = Readonly<{
  connectionId: string;
  name: string;
  surface: Readonly<{ kind: "mcp" | "openapi"; origin: string }>;
  credentialKind: Credential["kind"];
  state: "active" | "reconnect_required" | "revoked";
  authorityVersion: number;
  grants: readonly Readonly<{
    agentId: string;
    tools: Tools;
    version: number;
  }>[];
}>;

/** The Agent's narrowed capability: only the owner opens the credential. */
export type NarrowFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;
