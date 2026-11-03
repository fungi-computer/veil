import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import { parseOpenApiTable } from "@fungi.computer/forage/openapi";
import { assertPublicHostName } from "../model-key-network.js";
import { createPublicEgressPolicy } from "../public-egress-policy.js";
import {
  ConnectionsError,
  credentialSchema,
  draftSchema,
  egressRefSchema,
  grantInputSchema,
  identifier,
  toolsSchema,
  type ConnectionDraft,
  type GrantInput,
  type ConnectionProjection,
  type ConnectionView,
  type ConnectionsOptions,
  type CustodyAddress,
  type EgressRef,
  type NarrowFetch,
  type SurfaceView,
} from "./contract.js";
import { admitRequest } from "./egress.js";

const attemptTtlMs = 10 * 60 * 1000;
const cleanupLimit = 5;

const json = <S extends Schema.Top>(schema: S) => Schema.fromJsonString(schema);
const connectionRow = Schema.Struct({
  id: identifier,
  name: Schema.String,
  surface: json(
    Schema.Struct({
      kind: Schema.Literals(["mcp", "openapi"]),
      url: Schema.String,
      table: Schema.NullOr(Schema.Unknown),
    }),
  ),
  credential: json(credentialSchema),
  locator: Schema.NullOr(Schema.String),
  state: Schema.Literals(["active", "reconnect_required", "revoked"]),
  authorityVersion: Schema.Number,
});
type ConnectionRow = typeof connectionRow.Type;
const grantRow = Schema.Struct({
  connectionId: identifier,
  agentId: identifier,
  tools: json(toolsSchema),
  grantor: identifier,
  version: Schema.Number,
  active: Schema.Literals([0, 1]),
});
const receiptRow = Schema.Struct({
  fingerprint: Schema.String,
  result: json(Schema.Struct({ connectionId: identifier })),
});
const cleanupRow = Schema.Struct({
  id: Schema.Number,
  connectionId: identifier,
  locator: Schema.String,
  credential: json(credentialSchema),
  attempts: Schema.Number,
});
const count = Schema.Struct({ n: Schema.Number });

function decode<S extends Schema.Decoder<unknown>>(
  schema: S,
  input: unknown,
): S["Type"] {
  try {
    return Schema.decodeUnknownSync(schema)(input);
  } catch {
    throw new ConnectionsError("invalid_input");
  }
}
const sync = <A>(operation: () => A) =>
  Effect.try({
    try: operation,
    catch: (cause) =>
      cause instanceof ConnectionsError
        ? cause
        : new ConnectionsError("unavailable", { cause }),
  });
const io = <A>(operation: () => Promise<A>) =>
  Effect.tryPromise({
    try: operation,
    catch: (cause) =>
      cause instanceof ConnectionsError
        ? cause
        : new ConnectionsError("unavailable", { cause }),
  });

/** One owner's connections: attempts, connections, grants, receipts and cleanup in its SQLite. */
export function createConnections(options: ConnectionsOptions) {
  const ownerId = decode(identifier, options.ownerId);
  const { sql, transactionSync } = options.store;
  const policy = createPublicEgressPolicy(options.egressPolicy);
  sql.exec(`
    CREATE TABLE IF NOT EXISTS veil_connection_attempts (
      state TEXT PRIMARY KEY, connectionId TEXT NOT NULL, actor TEXT NOT NULL,
      status TEXT NOT NULL, expiresAt INTEGER NOT NULL,
      pkceVerifierSealed TEXT, issuer TEXT) STRICT;
    CREATE TABLE IF NOT EXISTS veil_connections (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, surface TEXT NOT NULL, credential TEXT NOT NULL,
      locator TEXT, state TEXT NOT NULL, authorityVersion INTEGER NOT NULL) STRICT;
    CREATE TABLE IF NOT EXISTS veil_connection_grants (
      connectionId TEXT NOT NULL, agentId TEXT NOT NULL, tools TEXT NOT NULL,
      grantor TEXT NOT NULL, version INTEGER NOT NULL, active INTEGER NOT NULL,
      PRIMARY KEY (connectionId, agentId)) STRICT;
    CREATE TABLE IF NOT EXISTS veil_connection_receipts (
      requestId TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result TEXT NOT NULL) STRICT;
    CREATE TABLE IF NOT EXISTS veil_connection_cleanup (
      id INTEGER PRIMARY KEY AUTOINCREMENT, connectionId TEXT NOT NULL, locator TEXT NOT NULL,
      credential TEXT NOT NULL, attempts INTEGER NOT NULL) STRICT;
    CREATE TABLE IF NOT EXISTS veil_connection_epoch (id INTEGER PRIMARY KEY CHECK (id = 1), revision INTEGER NOT NULL) STRICT;
    INSERT OR IGNORE INTO veil_connection_epoch VALUES (1, 1);`);

  const rows = <S extends Schema.Decoder<unknown>>(
    schema: S,
    statement: string,
    ...bindings: (string | number | null)[]
  ) =>
    sql
      .exec(statement, ...bindings)
      .toArray()
      .map((row) => decode(schema, row));
  const bump = () =>
    sql.exec("UPDATE veil_connection_epoch SET revision = revision + 1");
  const authorize = (actor: string, purpose: "manage" | "grantor") => {
    decode(identifier, actor);
    if (!options.authorize(actor, purpose))
      throw new ConnectionsError("denied");
  };
  const connection = (id: string): ConnectionRow => {
    const row = rows(
      connectionRow,
      "SELECT * FROM veil_connections WHERE id = ?",
      id,
    )[0];
    if (!row) throw new ConnectionsError("denied");
    return row;
  };
  const grant = (id: string, agentId: string) =>
    rows(
      grantRow,
      "SELECT * FROM veil_connection_grants WHERE connectionId = ? AND agentId = ?",
      id,
      agentId,
    )[0];
  const address = (row: ConnectionRow): CustodyAddress => ({
    ownerId,
    connectionId: row.id,
    credential: row.credential,
  });

  /** The surface URL must be public https with nothing the owner did not choose to send. */
  const publicUrl = (value: string) => {
    if (!URL.canParse(value)) throw new ConnectionsError("invalid_input");
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      throw new ConnectionsError("invalid_input");
    try {
      assertPublicHostName(url.hostname);
      policy.destination(url);
    } catch (cause) {
      throw new ConnectionsError("denied", { cause });
    }
    return url.href;
  };

  const sweep = () =>
    Effect.gen(function* () {
      const due = yield* sync(() =>
        rows(
          cleanupRow,
          "SELECT * FROM veil_connection_cleanup WHERE attempts < ?",
          cleanupLimit,
        ),
      );
      for (const job of due) {
        const outcome = yield* options.custody
          .remove(
            {
              ownerId,
              connectionId: job.connectionId,
              credential: job.credential,
            },
            job.locator,
          )
          .pipe(Effect.result);
        yield* sync(() => {
          if (outcome._tag === "Success")
            sql.exec(
              "DELETE FROM veil_connection_cleanup WHERE id = ?",
              job.id,
            );
          else
            sql.exec(
              "UPDATE veil_connection_cleanup SET attempts = attempts + 1 WHERE id = ?",
              job.id,
            );
        });
      }
    });
  const enqueueCleanup = (row: ConnectionRow) => {
    if (row.locator !== null)
      sql.exec(
        "INSERT INTO veil_connection_cleanup (connectionId, locator, credential, attempts) VALUES (?, ?, ?, 0)",
        row.id,
        row.locator,
        JSON.stringify(row.credential),
      );
  };

  const fingerprint = (draft: ConnectionDraft) =>
    JSON.stringify([
      draft.name,
      draft.surface.kind,
      "url" in draft.surface ? draft.surface.url : draft.surface.baseUrl,
      draft.credential,
      draft.secret !== undefined,
    ]);

  const begin = (actor: string, input: ConnectionDraft) =>
    Effect.gen(function* () {
      const draft = yield* sync(() => {
        authorize(actor, "manage");
        const parsed = decode(draftSchema, input);
        if (
          parsed.credential.kind === "static"
            ? parsed.secret === undefined
            : parsed.secret !== undefined
        )
          throw new ConnectionsError("invalid_input");
        return parsed;
      });
      const replay = yield* sync(() => {
        const receipt = rows(
          receiptRow,
          "SELECT fingerprint, result FROM veil_connection_receipts WHERE requestId = ?",
          draft.requestId,
        )[0];
        if (!receipt) return null;
        if (receipt.fingerprint !== fingerprint(draft))
          throw new ConnectionsError("conflict");
        return receipt.result.connectionId;
      });
      if (replay !== null) return { connectionId: replay, authorizeUrl: null };
      const endpoint = yield* sync(() =>
        publicUrl(
          draft.surface.kind === "mcp"
            ? draft.surface.url
            : draft.surface.baseUrl,
        ),
      );
      const surface = draft.surface;
      const table =
        surface.kind === "openapi"
          ? (yield* io(() => parseOpenApiTable(surface.table))).operations
          : null;
      const connectionId = options.ids();
      const state = options.ids();
      yield* sync(() => {
        decode(identifier, connectionId);
        sql.exec(
          "INSERT INTO veil_connection_attempts (state, connectionId, actor, status, expiresAt) VALUES (?, ?, ?, 'pending', ?)",
          state,
          connectionId,
          actor,
          options.clock() + attemptTtlMs,
        );
      });
      const addr = { ownerId, connectionId, credential: draft.credential };
      const locator =
        draft.secret === undefined
          ? null
          : yield* options.custody.put(addr, draft.secret);
      const stored: ConnectionRow = {
        id: connectionId,
        name: draft.name,
        credential: draft.credential,
        locator,
        state: "active",
        authorityVersion: 1,
        surface: {
          kind: draft.surface.kind,
          url: endpoint,
          table,
        },
      };
      return yield* sync(() =>
        transactionSync(() => {
          authorize(actor, "manage");
          const attempt = rows(
            count,
            "SELECT COUNT(*) AS n FROM veil_connection_attempts WHERE state = ? AND status = 'pending' AND expiresAt > ?",
            state,
            options.clock(),
          )[0];
          if (attempt?.n !== 1) throw new ConnectionsError("denied");
          sql.exec(
            "INSERT INTO veil_connections VALUES (?, ?, ?, ?, ?, 'active', 1)",
            stored.id,
            stored.name,
            JSON.stringify(stored.surface),
            JSON.stringify(stored.credential),
            stored.locator,
          );
          sql.exec(
            "UPDATE veil_connection_attempts SET status = 'completed' WHERE state = ?",
            state,
          );
          sql.exec(
            "INSERT INTO veil_connection_receipts VALUES (?, ?, ?)",
            draft.requestId,
            fingerprint(draft),
            JSON.stringify({ connectionId }),
          );
          bump();
          return { connectionId, authorizeUrl: null };
        }),
      ).pipe(
        Effect.tapError(() =>
          sync(() => {
            enqueueCleanup(stored);
          }),
        ),
      );
    });

  const grantTo = (actor: string, input: GrantInput) =>
    sync(() =>
      transactionSync(() => {
        authorize(actor, "manage");
        const wanted = decode(grantInputSchema, input);
        const row = connection(wanted.connectionId);
        if (row.state === "revoked") throw new ConnectionsError("revoked");
        if (
          wanted.tools === "all"
            ? false
            : row.surface.kind !== "mcp" && wanted.tools.length === 0
        )
          throw new ConnectionsError("invalid_input");
        const tools = JSON.stringify(wanted.tools);
        const existing = grant(wanted.connectionId, wanted.agentId);
        if (existing?.active === 1 && JSON.stringify(existing.tools) === tools)
          return { grantVersion: existing.version };
        const next = (existing?.version ?? 0) + 1;
        sql.exec(
          `INSERT INTO veil_connection_grants VALUES (?, ?, ?, ?, ?, 1)
           ON CONFLICT (connectionId, agentId) DO UPDATE SET tools = excluded.tools, grantor = excluded.grantor, version = excluded.version, active = 1`,
          wanted.connectionId,
          wanted.agentId,
          tools,
          actor,
          next,
        );
        bump();
        return { grantVersion: next };
      }),
    );

  const ungrant = (
    actor: string,
    input: { connectionId: string; agentId: string },
  ) =>
    sync(() => {
      transactionSync(() => {
        authorize(actor, "manage");
        const wanted = decode(
          Schema.Struct({ connectionId: identifier, agentId: identifier }),
          input,
        );
        const existing = grant(wanted.connectionId, wanted.agentId);
        if (existing?.active !== 1) return;
        sql.exec(
          "UPDATE veil_connection_grants SET active = 0, version = version + 1 WHERE connectionId = ? AND agentId = ?",
          wanted.connectionId,
          wanted.agentId,
        );
        bump();
      });
    });

  const revoke = (actor: string, input: { connectionId: string }) =>
    Effect.gen(function* () {
      yield* sync(() => {
        transactionSync(() => {
          authorize(actor, "manage");
          const row = connection(decode(identifier, input.connectionId));
          if (row.state === "revoked") return;
          sql.exec(
            "UPDATE veil_connections SET state = 'revoked', locator = NULL, authorityVersion = authorityVersion + 1 WHERE id = ?",
            row.id,
          );
          sql.exec(
            "UPDATE veil_connection_grants SET active = 0, version = version + 1 WHERE connectionId = ? AND active = 1",
            row.id,
          );
          enqueueCleanup(row);
          bump();
        });
      });
      yield* sweep();
    });

  const projection = (agentId: string) =>
    Effect.gen(function* () {
      const stored = yield* sync(() => {
        decode(identifier, agentId);
        const revision =
          rows(
            Schema.Struct({ revision: Schema.Number }),
            "SELECT revision FROM veil_connection_epoch",
          )[0]?.revision ?? 1;
        const granted = rows(
          grantRow,
          "SELECT * FROM veil_connection_grants WHERE agentId = ? AND active = 1",
          agentId,
        );
        return {
          revision,
          granted: granted
            .map((g) => ({ g, row: connection(g.connectionId) }))
            .filter(({ row }) => row.state === "active"),
        };
      });
      const connections = [];
      for (const { g, row } of stored.granted) {
        const surface: SurfaceView =
          row.surface.kind === "mcp"
            ? { kind: "mcp", url: row.surface.url }
            : {
                kind: "openapi",
                baseUrl: row.surface.url,
                table: (yield* io(() => parseOpenApiTable(row.surface.table)))
                  .operations,
              };
        connections.push({
          connectionId: row.id,
          name: row.name,
          surface,
          tools: g.tools,
          authorityVersion: row.authorityVersion,
          grantVersion: g.version,
        });
      }
      return {
        revision: stored.revision,
        connections,
      } satisfies ConnectionProjection;
    });

  const list = (actor: string) =>
    sync(() => {
      authorize(actor, "manage");
      return rows(
        connectionRow,
        "SELECT * FROM veil_connections ORDER BY id",
      ).map((row): ConnectionView => ({
        connectionId: row.id,
        name: row.name,
        surface: {
          kind: row.surface.kind,
          origin: new URL(row.surface.url).origin,
        },
        credentialKind: row.credential.kind,
        state: row.state,
        authorityVersion: row.authorityVersion,
        grants: rows(
          grantRow,
          "SELECT * FROM veil_connection_grants WHERE connectionId = ? AND active = 1",
          row.id,
        ).map((g) => ({
          agentId: g.agentId,
          tools: g.tools,
          version: g.version,
        })),
      }));
    });

  /** The grant, the connection and the grantor must all still stand. */
  const admitted = (agentId: string, ref: EgressRef) => {
    decode(identifier, agentId);
    const row = connection(ref.connectionId);
    const held = grant(ref.connectionId, agentId);
    if (
      row.state === "revoked" ||
      held?.active !== 1 ||
      held.version !== ref.grantVersion
    )
      throw new ConnectionsError("revoked");
    if (row.state === "reconnect_required")
      throw new ConnectionsError("reconnect_required");
    authorize(held.grantor, "grantor");
    return { row, tools: held.tools };
  };

  const egress = (agentId: string, input: EgressRef): NarrowFetch => {
    const ref = decode(egressRefSchema, input);
    return (target, init) =>
      Effect.runPromise(
        Effect.gen(function* () {
          const { row, tools } = yield* sync(() => admitted(agentId, ref));
          const request = yield* io(() =>
            admitRequest(
              { kind: row.surface.kind, url: row.surface.url },
              tools,
              new Request(target, init),
              policy,
            ),
          );
          if (row.locator === null && row.credential.kind === "static")
            return yield* Effect.fail(new ConnectionsError("denied"));
          const response = yield* options.custody
            .inject(address(row), row.locator ?? "", request)
            .pipe(
              Effect.tapError((error) =>
                error.code === "reconnect_required"
                  ? sync(() =>
                      sql.exec(
                        "UPDATE veil_connections SET state = 'reconnect_required', authorityVersion = authorityVersion + 1 WHERE id = ? AND state = 'active'",
                        row.id,
                      ),
                    )
                  : Effect.void,
              ),
            );
          const stillCurrent = yield* sync(() => admitted(agentId, ref)).pipe(
            Effect.result,
          );
          if (
            stillCurrent._tag === "Failure" ||
            response.redirected ||
            (response.status >= 300 && response.status < 400)
          ) {
            yield* io(() => response.body?.cancel() ?? Promise.resolve());
            return yield* Effect.fail(
              stillCurrent._tag === "Failure"
                ? stillCurrent.failure
                : new ConnectionsError("invalid_response"),
            );
          }
          return response;
        }),
      );
  };

  return {
    begin,
    grant: grantTo,
    ungrant,
    revoke,
    projection,
    list,
    egress,
    sweep,
  };
}
