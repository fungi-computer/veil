import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import { ConnectionsError, credentialSchema, identifier } from "./contract.js";

export const json = <S extends Schema.Top>(schema: S) =>
  Schema.fromJsonString(schema);
export const connectionRow = Schema.Struct({
  id: identifier,
  name: Schema.String,
  surface: json(
    Schema.Struct({
      kind: Schema.Literals(["mcp", "openapi"]),
      url: Schema.String,
      table: Schema.NullOr(Schema.Array(Schema.Unknown)),
      /** Digest of the decoded table, kept so listings need no decoding. */
      digest: Schema.optional(Schema.NullOr(Schema.String)),
      /** Display text for owners; the unique `name` is the binding. */
      label: Schema.optional(Schema.String),
    }),
  ),
  credential: json(credentialSchema),
  locator: Schema.NullOr(Schema.String),
  state: Schema.Literals([
    "pending",
    "active",
    "reconnect_required",
    "revoked",
  ]),
  authorityVersion: Schema.Number,
  version: Schema.Number,
});
export type ConnectionRow = typeof connectionRow.Type;
export const attemptRow = Schema.Struct({
  state: Schema.String,
  connectionId: identifier,
  actor: identifier,
  status: Schema.String,
  expiresAt: Schema.Number,
  pkceVerifierSealed: Schema.NullOr(Schema.String),
  /** The authorization server, or `custody:<integration>` when a custodian runs the sign-in. */
  issuer: Schema.NullOr(Schema.String),
});
export type AttemptRow = typeof attemptRow.Type;
export const registryRow = Schema.Struct({ locator: Schema.String });
export function decode<S extends Schema.Decoder<unknown>>(
  schema: S,
  input: unknown,
): S["Type"] {
  try {
    return Schema.decodeUnknownSync(schema)(input);
  } catch {
    throw new ConnectionsError("invalid_input");
  }
}
export const sync = <A>(operation: () => A) =>
  Effect.try({
    try: operation,
    catch: (cause) =>
      cause instanceof ConnectionsError
        ? cause
        : new ConnectionsError("unavailable", { cause }),
  });
export const io = <A>(operation: () => Promise<A>) =>
  Effect.tryPromise({
    try: operation,
    catch: (cause) =>
      cause instanceof ConnectionsError
        ? cause
        : new ConnectionsError("unavailable", { cause }),
  });

export const cleanupRow = Schema.Struct({
  id: Schema.Number,
  connectionId: identifier,
  locator: Schema.String,
  credential: json(credentialSchema),
  attempts: Schema.Number,
});
export const count = Schema.Struct({ n: Schema.Number });
