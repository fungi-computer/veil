import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import { assertPublicHostName } from "../model-key-network.js";
import { createPublicEgressPolicy } from "../public-egress-policy.js";
import {
  ConnectionsError,
  attemptTtlMs,
  callInputSchema,
  completeInputSchema,
  draftSchema,
  egressRefSchema,
  grantInputSchema,
  identifier,
  toolsSchema,
  type CallInput,
  type ConnectionDraft,
  type Tools,
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
import {
  admits,
  boundedText,
  decodeTable,
  operationOutput,
  operationRequest,
} from "./openapi.js";
import type { OpenApiOperation } from "@fungi.computer/forage/openapi";
import { createCleanup } from "./cleanup.js";
import {
  attemptRow,
  connectionRow,
  count,
  decode,
  io,
  json,
  registryRow,
  sync,
  type AttemptRow,
  type ConnectionRow,
} from "./internal.js";
import { createOAuthFlow, type OAuthStore } from "./oauth-flow.js";
import { listMcpTools } from "./discover.js";
import { createUpdate } from "./update.js";

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
  result: json(
    Schema.Struct({
      connectionId: identifier,
      authorizeUrl: Schema.optional(Schema.String),
      attemptId: Schema.optional(Schema.String),
      version: Schema.optional(Schema.Number),
    }),
  ),
});

/** One owner's connections: attempts, connections, grants, receipts and cleanup in its SQLite. */
export function createConnections(options: ConnectionsOptions) {
  const ownerId = decode(identifier, options.ownerId);
  const { sql } = options.store;
  // A Durable Object's storage must be called as a method, never detached.
  const transactionSync = <A>(body: () => A) =>
    options.store.transactionSync(body);
  const policy = createPublicEgressPolicy(options.egressPolicy);
  sql.exec(`
    CREATE TABLE IF NOT EXISTS veil_connection_attempts (
      state TEXT PRIMARY KEY, connectionId TEXT NOT NULL, actor TEXT NOT NULL,
      status TEXT NOT NULL, expiresAt INTEGER NOT NULL,
      pkceVerifierSealed TEXT, issuer TEXT) STRICT;
    CREATE TABLE IF NOT EXISTS veil_connections (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, surface TEXT NOT NULL, credential TEXT NOT NULL,
      locator TEXT, state TEXT NOT NULL, authorityVersion INTEGER NOT NULL,
      version INTEGER NOT NULL) STRICT;
    CREATE TABLE IF NOT EXISTS veil_connection_grants (
      connectionId TEXT NOT NULL, agentId TEXT NOT NULL, tools TEXT NOT NULL,
      grantor TEXT NOT NULL, version INTEGER NOT NULL, active INTEGER NOT NULL,
      PRIMARY KEY (connectionId, agentId)) STRICT;
    CREATE TABLE IF NOT EXISTS veil_connection_receipts (
      requestId TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, result TEXT NOT NULL) STRICT;
    CREATE TABLE IF NOT EXISTS veil_connection_cleanup (
      id INTEGER PRIMARY KEY AUTOINCREMENT, connectionId TEXT NOT NULL, locator TEXT NOT NULL,
      credential TEXT NOT NULL, attempts INTEGER NOT NULL) STRICT;
    CREATE TABLE IF NOT EXISTS veil_oauth_clients (
      issuer TEXT PRIMARY KEY, locator TEXT NOT NULL) STRICT;
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
  /** The origins a named provider's credential may reach, or nothing when this host does not hold it. */
  const providerOrigins = (provider: string) =>
    options.oauth?.providers?.[provider]?.apiOrigins ??
    options.custodyProviders?.[provider]?.apiOrigins;
  const assertProviderOrigin = (
    credential: ConnectionRow["credential"],
    target: string,
    refusal: "invalid_input" | "denied",
  ) => {
    if (credential.kind !== "oauth" || credential.provider === undefined)
      return;
    const origins = providerOrigins(credential.provider);
    // A provider this host no longer holds must be connected again.
    if (origins === undefined) throw new ConnectionsError("reconnect_required");
    if (!origins.includes(new URL(target).origin))
      throw new ConnectionsError(refusal);
  };
  /** One live connection per binding name, so an Agent's module name is unambiguous. */
  const assertNameFree = (name: string, exceptId: string | null) => {
    const taken = rows(
      count,
      "SELECT COUNT(*) AS n FROM veil_connections WHERE name = ? AND state != 'revoked' AND id != ?",
      name,
      exceptId ?? "",
    )[0];
    if (taken === undefined || taken.n > 0)
      throw new ConnectionsError("conflict");
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

  const {
    cleanupPending,
    cleanupRetryPending,
    sweep,
    enqueueLocator,
    enqueueCleanup,
    markReconnect,
    retireAttempt,
  } = createCleanup({
    ownerId,
    custody: options.custody,
    clock: options.clock,
    sql,
    transactionSync,
    rows,
    bump,
  });

  const fingerprint = (draft: ConnectionDraft) =>
    JSON.stringify([
      draft.name,
      draft.label ?? null,
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
        const wantsSecret =
          parsed.credential.kind === "static"
            ? "required"
            : parsed.credential.kind === "oauth"
              ? "client"
              : "never";
        if (
          (wantsSecret === "required" && parsed.secret === undefined) ||
          (wantsSecret === "never" && parsed.secret !== undefined) ||
          (parsed.credential.kind === "oauth" &&
            // An MCP server signs in at itself; a REST connection through a
            // provider the operator registered, with the operator's client; or
            // a custodian that runs the authorization (its integration id).
            (parsed.credential.provider === undefined
              ? parsed.surface.kind !== "mcp" ||
                (parsed.secret !== undefined &&
                  parsed.credential.clientId === undefined)
              : parsed.secret !== undefined ||
                parsed.credential.clientId !== undefined ||
                (options.oauth?.providers?.[parsed.credential.provider] ===
                undefined
                  ? options.custody.connect === undefined ||
                    options.custodyProviders?.[parsed.credential.provider] ===
                      undefined
                  : parsed.surface.kind !== "openapi")))
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
        return receipt.result;
      });
      if (replay !== null)
        return {
          connectionId: replay.connectionId,
          authorizeUrl: replay.authorizeUrl ?? null,
          attemptId: replay.attemptId ?? null,
        };
      yield* sync(() => {
        assertNameFree(draft.name, null);
      });
      const endpoint = yield* sync(() =>
        publicUrl(
          draft.surface.kind === "openapi"
            ? draft.surface.baseUrl
            : draft.surface.url,
        ),
      );
      // A provider's credential is sent only to the origins its operator declared.
      yield* sync(() => {
        assertProviderOrigin(draft.credential, endpoint, "invalid_input");
      });
      const surface = draft.surface;
      const decoded =
        surface.kind === "openapi"
          ? yield* io(() => decodeTable(surface.table))
          : null;
      if (draft.credential.kind === "oauth") {
        const table =
          decoded === null
            ? null
            : { table: decoded.operations, digest: decoded.digest };
        const viaCustodian =
          draft.credential.provider !== undefined &&
          options.oauth?.providers?.[draft.credential.provider] === undefined;
        return yield* viaCustodian
          ? oauthFlow.beginCustody(
              actor,
              draft,
              draft.credential,
              endpoint,
              fingerprint(draft),
              table,
              draft.surface.kind,
            )
          : oauthFlow.begin(
              actor,
              draft,
              draft.credential,
              endpoint,
              fingerprint(draft),
              table,
            );
      }
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
        version: 1,
        surface: {
          kind: draft.surface.kind,
          url: endpoint,
          table: decoded?.operations ?? null,
          digest: decoded?.digest ?? null,
          label: draft.label ?? draft.name,
        },
      };
      return yield* sync(() =>
        transactionSync(() => {
          authorize(actor, "manage");
          assertNameFree(stored.name, null);
          const attempt = rows(
            count,
            "SELECT COUNT(*) AS n FROM veil_connection_attempts WHERE state = ? AND status = 'pending' AND expiresAt > ?",
            state,
            options.clock(),
          )[0];
          if (attempt?.n !== 1) throw new ConnectionsError("denied");
          sql.exec(
            "INSERT INTO veil_connections VALUES (?, ?, ?, ?, ?, 'active', 1, 1)",
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
          return { connectionId, authorizeUrl: null, attemptId: null };
        }),
      ).pipe(
        Effect.tapError(() =>
          sync(() => {
            enqueueCleanup(stored);
          }),
        ),
      );
    });

  const oauthStore: OAuthStore = {
    connection,
    recordPending: (input) => {
      transactionSync(() => {
        authorize(input.actor, "manage");
        const stored = input.connection;
        assertNameFree(stored.name, null);
        sql.exec(
          "INSERT INTO veil_connections VALUES (?, ?, ?, ?, NULL, 'pending', 1, 1)",
          stored.id,
          stored.name,
          JSON.stringify(stored.surface),
          JSON.stringify(stored.credential),
        );
        sql.exec(
          "INSERT INTO veil_connection_attempts VALUES (?, ?, ?, 'pending', ?, ?, ?)",
          input.state,
          stored.id,
          input.actor,
          options.clock() + attemptTtlMs,
          input.attemptLocator,
          input.issuer,
        );
        sql.exec(
          "INSERT INTO veil_connection_receipts VALUES (?, ?, ?)",
          input.requestId,
          input.fingerprint,
          JSON.stringify({
            connectionId: stored.id,
            authorizeUrl: input.authorizeUrl,
            attemptId: input.state,
          }),
        );
        bump();
      });
    },
    claimCustody: (state, principalId) =>
      transactionSync(() => {
        if (!state.startsWith(`${ownerId}.`))
          throw new ConnectionsError("denied");
        const attempt = rows(
          attemptRow,
          "SELECT * FROM veil_connection_attempts WHERE state = ?",
          state,
        )[0];
        // A browser attempt holds a sealed verifier; only a custodian's has none.
        if (
          attempt?.status !== "pending" ||
          attempt.pkceVerifierSealed !== null ||
          attempt.actor !== principalId
        )
          throw new ConnectionsError("denied");
        if (attempt.expiresAt <= options.clock()) {
          retireAttempt(attempt, "expired");
          return { attempt, expired: true };
        }
        sql.exec(
          "UPDATE veil_connection_attempts SET status = 'consumed' WHERE state = ?",
          state,
        );
        return { attempt, expired: false };
      }),
    claim: (actor, input) =>
      transactionSync(() => {
        authorize(actor, "manage");
        const wanted = decode(completeInputSchema, input);
        if (!wanted.state.startsWith(`${ownerId}.`))
          throw new ConnectionsError("denied");
        const attempt = rows(
          attemptRow,
          "SELECT * FROM veil_connection_attempts WHERE state = ?",
          wanted.state,
        )[0];
        if (
          attempt?.status !== "pending" ||
          attempt.actor !== actor ||
          attempt.pkceVerifierSealed === null
        )
          throw new ConnectionsError("denied");
        if (attempt.expiresAt <= options.clock()) {
          retireAttempt(attempt, "expired");
          return { attempt, wanted, expired: true };
        }
        sql.exec(
          "UPDATE veil_connection_attempts SET status = 'consumed' WHERE state = ?",
          attempt.state,
        );
        return { attempt, wanted, expired: false };
      }),
    fail: (attempt) => {
      transactionSync(() => {
        retireAttempt(attempt, "failed");
      });
    },
    activate: (row, attempt, locator) =>
      transactionSync(() => {
        const current = connection(row.id);
        if (current.state !== "pending") return false;
        sql.exec(
          "UPDATE veil_connections SET state = 'active', locator = ?, authorityVersion = authorityVersion + 1 WHERE id = ?",
          locator,
          row.id,
        );
        sql.exec(
          "UPDATE veil_connection_attempts SET status = 'completed', pkceVerifierSealed = NULL WHERE state = ?",
          attempt.state,
        );
        if (attempt.pkceVerifierSealed !== null)
          enqueueLocator(row.id, attempt.pkceVerifierSealed, row.credential);
        bump();
        return true;
      }),
    discard: (connectionId, locator, credential) => {
      transactionSync(() => {
        enqueueLocator(connectionId, locator, credential);
      });
    },
    swap: (row, held, locator) =>
      transactionSync(() => {
        const current = connection(row.id);
        if (current.state !== "active" || current.locator !== held)
          return current.state;
        sql.exec(
          "UPDATE veil_connections SET locator = ? WHERE id = ?",
          locator,
          row.id,
        );
        enqueueLocator(row.id, held, row.credential);
        return "applied";
      }),
    clientLocator: (issuer) =>
      rows(
        registryRow,
        "SELECT locator FROM veil_oauth_clients WHERE issuer = ?",
        issuer,
      )[0]?.locator,
    saveClientLocator: (issuer, locator) => {
      transactionSync(() => {
        const old = rows(
          registryRow,
          "SELECT locator FROM veil_oauth_clients WHERE issuer = ?",
          issuer,
        )[0];
        sql.exec(
          "INSERT OR REPLACE INTO veil_oauth_clients VALUES (?, ?)",
          issuer,
          locator,
        );
        if (old !== undefined)
          enqueueLocator("oauth-clients", old.locator, { kind: "oauth" });
      });
    },
  };
  const oauthFlow = createOAuthFlow({
    ownerId,
    custody: options.custody,
    oauth: options.oauth,
    clock: options.clock,
    ids: options.ids,
    policy,
    store: oauthStore,
    sweep,
  });

  const grantTo = (actor: string, input: GrantInput) =>
    sync(() =>
      transactionSync(() => {
        authorize(actor, "manage");
        const wanted = decode(grantInputSchema, input);
        const row = connection(wanted.connectionId);
        if (row.state === "revoked") throw new ConnectionsError("revoked");
        if (
          wanted.tools !== "all" &&
          (Array.isArray(wanted.tools)
            ? row.surface.kind !== "mcp" && wanted.tools.length === 0
            : row.surface.kind !== "openapi")
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
          for (const attempt of rows(
            attemptRow,
            "SELECT * FROM veil_connection_attempts WHERE connectionId = ? AND status IN ('pending', 'consumed')",
            row.id,
          ))
            retireAttempt(attempt, "revoked");
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
        let surface: SurfaceView = { kind: "mcp", url: row.surface.url };
        if (row.surface.kind === "openapi") {
          const decoded = yield* io(() => decodeTable(row.surface.table));
          surface = {
            kind: "openapi",
            baseUrl: row.surface.url,
            table: decoded.operations,
            digest: decoded.digest,
          };
        }
        connections.push({
          connectionId: row.id,
          name: row.name,
          surface,
          tools: g.tools,
          version: row.version,
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
        label: row.surface.label ?? row.name,
        surface: {
          kind: row.surface.kind,
          origin: new URL(row.surface.url).origin,
          url: row.surface.url,
          digest: row.surface.digest ?? null,
        },
        credentialKind: row.credential.kind,
        credential: row.credential,
        state: row.state,
        version: row.version,
        authorityVersion: row.authorityVersion,
        grants: rows(
          grantRow,
          "SELECT * FROM veil_connection_grants WHERE connectionId = ? AND active = 1",
          row.id,
        ).map((g) => ({
          agentId: g.agentId,
          tools: g.tools,
          version: g.version,
          grantor: g.grantor,
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
    if (row.state === "pending") throw new ConnectionsError("pending");
    if (row.state === "reconnect_required")
      throw new ConnectionsError("reconnect_required");
    authorize(held.grantor, "grantor");
    return { row, tools: held.tools, grantor: held.grantor, agentId };
  };

  /**
   * One request through every gate: the grant, the host's last live check, the
   * credential at the owner, and the grant again on the way back.
   */
  const deliver = (
    admit: () => ReturnType<typeof admitted>,
    prepare: (
      row: ConnectionRow,
      tools: Tools,
    ) => Effect.Effect<
      Readonly<{
        request: Request;
        operation: Readonly<{
          name: string;
          effect: "read" | "write" | null;
        }> | null;
      }>,
      ConnectionsError
    >,
  ) =>
    Effect.gen(function* () {
      const { row, tools, grantor, agentId } = yield* sync(admit);
      const { request, operation } = yield* prepare(row, tools);
      const verdict = options.check;
      if (
        verdict !== undefined &&
        !(yield* io(() =>
          verdict(grantor, { agentId, connectionId: row.id, tools }, operation),
        ))
      )
        return yield* Effect.fail(new ConnectionsError("denied"));
      yield* sync(admit);
      yield* sync(() => {
        assertProviderOrigin(row.credential, request.url, "denied");
      });
      if (row.locator === null && row.credential.kind === "static")
        return yield* Effect.fail(new ConnectionsError("denied"));
      const response =
        yield* // A custodian that runs the sign-in refreshes the token itself.
        (
          row.credential.kind === "oauth" && options.custody.open !== undefined
            ? oauthFlow.send(row, request)
            : options.custody.inject(address(row), row.locator ?? "", request)
        ).pipe(
          Effect.tapError((error) =>
            error.code === "reconnect_required"
              ? sync(() => {
                  markReconnect(row.id);
                })
              : Effect.void,
          ),
        );
      const stillCurrent = yield* sync(admit).pipe(Effect.result);
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
    });

  const fetchThrough = (
    admit: () => ReturnType<typeof admitted>,
    target: Parameters<NarrowFetch>[0],
    init: Parameters<NarrowFetch>[1],
  ) =>
    Effect.runPromise(
      deliver(admit, (row, tools) => {
        const { kind, url } = row.surface;
        return kind === "openapi" && tools !== "all"
          ? // Effect and name grants are enforced per operation, by `call`.
            Effect.fail(new ConnectionsError("denied"))
          : io(() =>
              admitRequest(
                { kind, url },
                tools,
                new Request(target, init),
                policy,
              ),
            ).pipe(Effect.map((request) => ({ request, operation: null })));
      }),
    );
  const egress = (agentId: string, input: EgressRef): NarrowFetch => {
    const ref = decode(egressRefSchema, input);
    return (target, init) =>
      fetchThrough(() => admitted(agentId, ref), target, init);
  };

  /** A typed OpenAPI operation: built from the stored table, checked against its stored schemas. */
  const callThrough = (
    admit: () => ReturnType<typeof admitted>,
    raw: CallInput,
  ) =>
    Effect.gen(function* () {
      const wanted = yield* sync(() => decode(callInputSchema, raw));
      let chosen: OpenApiOperation | undefined;
      const response = yield* deliver(admit, (row, tools) =>
        Effect.gen(function* () {
          if (row.surface.kind !== "openapi")
            return yield* Effect.fail(new ConnectionsError("unsupported"));
          const table = yield* io(() => decodeTable(row.surface.table));
          chosen = table.operations.find(
            (candidate) => candidate.name === wanted.operation,
          );
          if (chosen === undefined || !admits(tools, chosen))
            return yield* Effect.fail(new ConnectionsError("denied"));
          const picked = chosen;
          const built = yield* io(() =>
            operationRequest(row.surface.url, picked, wanted.input),
          );
          const request = yield* io(() =>
            admitRequest(
              { kind: "openapi", url: row.surface.url },
              "all",
              built,
              policy,
            ),
          );
          return {
            request,
            operation: { name: picked.name, effect: picked.effect },
          };
        }),
      );
      const operation = chosen;
      if (operation === undefined)
        return yield* Effect.fail(new ConnectionsError("denied"));
      const text = yield* io(() => boundedText(response));
      // A grant ended while the body streamed: nothing read may be returned.
      yield* sync(admit);
      if (!response.ok)
        return yield* Effect.fail(new ConnectionsError("invalid_response"));
      return yield* io(() => operationOutput(operation, text));
    });

  const call = (agentId: string, input: EgressRef, raw: CallInput) => {
    const ref = decode(egressRefSchema, input);
    return callThrough(() => admitted(agentId, ref), raw);
  };

  /** The owner as sender: no Agent grant, and a version they last saw, when they name one. */
  const ownerAdmit = (
    actor: string,
    connectionId: string,
    expectedVersion: number | null,
  ) => {
    authorize(actor, "manage");
    const row = connection(connectionId);
    if (row.state === "revoked") throw new ConnectionsError("revoked");
    if (expectedVersion !== null && row.version !== expectedVersion)
      throw new ConnectionsError("conflict");
    if (row.state !== "active") throw new ConnectionsError("pending");
    return {
      row,
      tools: "all" as const,
      grantor: actor,
      agentId: `owner:${actor}`,
    };
  };
  const ownerCall = (
    actor: string,
    at: Readonly<{ connectionId: string; expectedVersion: number }>,
    raw: CallInput,
  ) =>
    callThrough(
      () => ownerAdmit(actor, at.connectionId, at.expectedVersion),
      raw,
    );
  /** The owner's own raw fetch to one connection, through the same gates. */
  const ownerFetch =
    (actor: string, connectionId: string): NarrowFetch =>
    (target, init) =>
      fetchThrough(() => ownerAdmit(actor, connectionId, null), target, init);
  /** The tools an MCP connection offers, listed by its owner. */
  const tools = (actor: string, connectionId: string) =>
    Effect.gen(function* () {
      const row = yield* sync(() => {
        authorize(actor, "manage");
        return connection(connectionId);
      });
      if (row.surface.kind !== "mcp")
        return yield* Effect.fail(new ConnectionsError("unsupported"));
      return yield* io(() =>
        listMcpTools(row.surface.url, ownerFetch(actor, connectionId)),
      );
    });

  /** The decoded operations of one OpenAPI connection, for its owner. */
  const operations = (actor: string, id: string) =>
    Effect.gen(function* () {
      const row = yield* sync(() => {
        authorize(actor, "manage");
        return connection(id);
      });
      if (row.surface.kind !== "openapi")
        return yield* Effect.fail(new ConnectionsError("unsupported"));
      return yield* io(() => decodeTable(row.surface.table));
    });

  /**
   * A custodian's signed completion can be lost. Ask it directly about each
   * open sign-in it is running and settle the ones it finished; bounded, and
   * harmless to repeat because the attempt is single use.
   */
  const awaitingCustody = () =>
    rows(
      attemptRow,
      "SELECT * FROM veil_connection_attempts WHERE status = 'pending' AND pkceVerifierSealed IS NULL AND issuer LIKE 'custody:%' AND expiresAt > ? ORDER BY expiresAt LIMIT 16",
      options.clock(),
    );
  const reconcileAttempt = (attempt: AttemptRow) =>
    Effect.gen(function* () {
      const find = options.custody.find;
      if (find === undefined) return null;
      const row = yield* sync(() => connection(attempt.connectionId));
      const found = yield* find(address(row), {
        state: attempt.state,
        actor: attempt.actor,
        integrationId: (attempt.issuer ?? "").slice("custody:".length),
      });
      if (found.status === "ambiguous")
        return yield* Effect.fail(new ConnectionsError("conflict"));
      if (found.status === "unresolved") return null;
      const done = yield* oauthFlow.completeCustody({
        state: attempt.state,
        locator: found.locator,
        principalId: attempt.actor,
        integrationId: (attempt.issuer ?? "").slice("custody:".length),
      });
      return done.connectionId;
    });
  /** The connections a custodian finished that no webhook told us about. */
  const reconcilePending = () =>
    Effect.gen(function* () {
      const settled: string[] = [];
      for (const attempt of yield* sync(awaitingCustody)) {
        const outcome = yield* reconcileAttempt(attempt).pipe(Effect.result);
        if (outcome._tag === "Success" && outcome.success !== null)
          settled.push(outcome.success);
      }
      return settled;
    });

  const update = createUpdate({
    ownerId,
    custody: options.custody,
    store: {
      authorize: (actor) => {
        authorize(actor, "manage");
      },
      connection,
      receipt: (requestId) => {
        const found = rows(
          receiptRow,
          "SELECT fingerprint, result FROM veil_connection_receipts WHERE requestId = ?",
          requestId,
        )[0];
        return found === undefined
          ? null
          : {
              stamp: found.fingerprint,
              connectionId: found.result.connectionId,
              version: found.result.version ?? 0,
            };
      },
      checkName: assertNameFree,
      publicUrl,
      commit: ({ actor, update: input, stamp, row, ...next }) =>
        transactionSync(() => {
          authorize(actor, "manage");
          const current = connection(row.id);
          if (
            current.version !== input.expectedVersion ||
            current.state !== row.state
          )
            throw new ConnectionsError("conflict");
          if (input.name !== undefined) assertNameFree(input.name, row.id);
          const version = current.version + 1;
          sql.exec(
            "UPDATE veil_connections SET name = ?, surface = ?, credential = ?, locator = ?, version = ?, authorityVersion = authorityVersion + 1 WHERE id = ?",
            input.name ?? current.name,
            JSON.stringify({
              ...current.surface,
              url: next.baseUrl,
              table: next.table,
              digest: next.digest,
              label: input.label ?? current.surface.label ?? current.name,
            }),
            JSON.stringify(next.credential),
            next.locator,
            version,
            row.id,
          );
          if (input.secret !== undefined && row.locator !== null)
            enqueueLocator(row.id, row.locator, row.credential);
          sql.exec(
            "INSERT INTO veil_connection_receipts VALUES (?, ?, ?)",
            input.requestId,
            stamp,
            JSON.stringify({ connectionId: row.id, version }),
          );
          bump();
          return { connectionId: row.id, version };
        }),
      discard: (connectionId, locator, credential) => {
        enqueueLocator(connectionId, locator, credential);
      },
    },
  });

  return {
    begin,
    complete: oauthFlow.complete,
    completeCustody: oauthFlow.completeCustody,
    grant: grantTo,
    ungrant,
    revoke,
    projection,
    list,
    egress,
    call,
    ownerCall,
    tools,
    operations,
    update,
    sweep,
    cleanupPending,
    cleanupRetryPending,
    reconcilePending,
    awaitingCustody: () => awaitingCustody().length,
  };
}
