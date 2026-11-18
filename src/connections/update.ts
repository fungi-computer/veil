import * as Effect from "effect/Effect";
import {
  ConnectionsError,
  updateInputSchema,
  type ConnectionsOptions,
  type HttpDestinations,
  type UpdateInput,
} from "./contract.js";
import { validateDestinations } from "./egress.js";
import { decode, io, sync, type ConnectionRow } from "./internal.js";
import { decodeTable } from "./openapi.js";

/** Whether a path prefix admits nothing outside the stored one, as egress matches it. */
const pathWithin = (stored: string | undefined, next: string | undefined) =>
  stored === undefined ||
  (next !== undefined &&
    (next === stored ||
      next.startsWith(stored.endsWith("/") ? stored : `${stored}/`)));

/**
 * Whether every next rule admits only requests a stored rule already admits:
 * the same exact host, a subset of its methods and a path at or below it.
 */
function narrowsDestinations(
  stored: HttpDestinations,
  next: HttpDestinations,
): boolean {
  return next.every((rule) =>
    stored.some(
      (held) =>
        held.host === rule.host &&
        rule.methods.every((method) => held.methods.includes(method)) &&
        pathWithin(held.pathPrefix, rule.pathPrefix),
    ),
  );
}

/** The owner's SQLite as `update` sees it; every method is one synchronous step or transaction. */
export type UpdateStore = Readonly<{
  authorize: (actor: string) => void;
  connection: (id: string) => ConnectionRow;
  /** A recorded update by request id, with the stamp it was recorded under. */
  receipt: (requestId: string) => Readonly<{
    stamp: string;
    connectionId: string;
    version: number;
  }> | null;
  checkName: (name: string, exceptId: string) => void;
  publicUrl: (value: string) => string;
  commit: (
    input: Readonly<{
      actor: string;
      update: UpdateInput;
      stamp: string;
      row: ConnectionRow;
      baseUrl: string;
      table: ConnectionRow["surface"]["table"];
      digest: string | null;
      destinations: HttpDestinations | undefined;
      credential: ConnectionRow["credential"];
      locator: string | null;
    }>,
  ) => { connectionId: string; version: number };
  /** Queue a sealed locator for deletion. */
  discard: (
    connectionId: string,
    locator: string,
    credential: ConnectionRow["credential"],
  ) => void;
}>;

/** Owner edits guarded by the version the owner last saw; replays are idempotent. */
export function createUpdate(deps: {
  ownerId: string;
  custody: ConnectionsOptions["custody"];
  store: UpdateStore;
}) {
  const { store } = deps;
  return (actor: string, raw: UpdateInput) =>
    Effect.gen(function* () {
      const input = yield* sync(() => {
        store.authorize(actor);
        const parsed = decode(updateInputSchema, raw);
        if (
          parsed.credential?.kind === "oauth" ||
          (parsed.credential?.kind === "static") !==
            (parsed.secret !== undefined)
        )
          throw new ConnectionsError(
            parsed.credential === undefined ? "invalid_input" : "unsupported",
          );
        return parsed;
      });
      const stamp = JSON.stringify([
        "update",
        input.connectionId,
        input.expectedVersion,
        input.name ?? null,
        input.label ?? null,
        input.baseUrl ?? null,
        input.table === undefined ? null : JSON.stringify(input.table),
        input.destinations ?? null,
        input.credential ?? null,
        input.secret !== undefined,
      ]);
      const replay = yield* sync(() => {
        const receipt = store.receipt(input.requestId);
        if (receipt !== null && receipt.stamp !== stamp)
          throw new ConnectionsError("conflict");
        return receipt;
      });
      if (replay !== null)
        return { connectionId: replay.connectionId, version: replay.version };
      const row = yield* sync(() => {
        const found = store.connection(input.connectionId);
        if (found.version !== input.expectedVersion)
          throw new ConnectionsError("conflict");
        if (found.state === "revoked" || found.state === "pending")
          throw new ConnectionsError(
            found.state === "revoked" ? "revoked" : "pending",
          );
        if (
          (input.table !== undefined || input.baseUrl !== undefined) &&
          found.surface.kind !== "openapi"
        )
          throw new ConnectionsError("invalid_input");
        if (input.destinations !== undefined) {
          if (found.surface.kind !== "http")
            throw new ConnectionsError("invalid_input");
          validateDestinations(input.destinations);
          // A value may only reach a host it was entered for: widening the
          // binding without re-entering the value would let a manager read it.
          if (
            input.secret === undefined &&
            !narrowsDestinations(
              found.surface.destinations ?? [],
              input.destinations,
            )
          )
            throw new ConnectionsError("denied");
        }
        // An HTTP secret is always a static value: it cannot lose its credential.
        if (
          found.surface.kind === "http" &&
          input.credential !== undefined &&
          input.credential.kind !== "static"
        )
          throw new ConnectionsError("invalid_input");
        // A new destination must not inherit a credential sealed for the old one.
        if (
          input.baseUrl !== undefined &&
          input.credential === undefined &&
          found.credential.kind !== "none" &&
          new URL(input.baseUrl).href !== found.surface.url
        )
          throw new ConnectionsError("invalid_input");
        if (input.name !== undefined) store.checkName(input.name, found.id);
        return found;
      });
      // An HTTP secret's first bound host stands for it where one origin is needed.
      const firstHost = input.destinations?.[0]?.host;
      const baseUrl = yield* sync(() =>
        firstHost !== undefined
          ? store.publicUrl(`https://${firstHost}/`)
          : input.baseUrl === undefined
            ? row.surface.url
            : store.publicUrl(input.baseUrl),
      );
      const next =
        input.table === undefined
          ? null
          : yield* io(() => decodeTable(input.table));
      const credential = input.credential ?? row.credential;
      const locator =
        input.secret === undefined
          ? row.locator
          : yield* deps.custody.put(
              { ownerId: deps.ownerId, connectionId: row.id, credential },
              input.secret,
            );
      return yield* sync(() =>
        store.commit({
          actor,
          update: input,
          stamp,
          row,
          baseUrl,
          table: next?.operations ?? row.surface.table,
          digest: next?.digest ?? row.surface.digest ?? null,
          destinations: input.destinations ?? row.surface.destinations,
          credential,
          locator,
        }),
      ).pipe(
        Effect.tapError(() =>
          sync(() => {
            if (input.secret !== undefined && locator !== null)
              store.discard(row.id, locator, credential);
          }),
        ),
      );
    });
}
