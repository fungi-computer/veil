import * as Effect from "effect/Effect";
import type * as Schema from "effect/Schema";
import type { ConnectionsOptions } from "./contract.js";
import {
  attemptRow,
  cleanupRow,
  connectionRow,
  count,
  sync,
  type AttemptRow,
  type ConnectionRow,
} from "./internal.js";

const cleanupLimit = 5;

/** The cleanup outbox, attempt retirement and reconnect marking over the owner's SQLite. */
export function createCleanup(deps: {
  ownerId: string;
  custody: ConnectionsOptions["custody"];
  clock: () => number;
  sql: ConnectionsOptions["store"]["sql"];
  transactionSync: <A>(body: () => A) => A;
  rows: <S extends Schema.Decoder<unknown>>(
    schema: S,
    statement: string,
    ...bindings: (string | number | null)[]
  ) => S["Type"][];
  bump: () => void;
}) {
  const { sql, rows, bump, transactionSync } = deps;
  /** Credentials still waiting to be deleted, including exhausted retries. */
  const cleanupPending = () =>
    rows(count, "SELECT COUNT(*) AS n FROM veil_connection_cleanup")[0]?.n ?? 0;
  /** Cleanup jobs eligible for another deletion attempt; hosts wake only for these. */
  const cleanupRetryPending = () =>
    rows(
      count,
      "SELECT COUNT(*) AS n FROM veil_connection_cleanup WHERE attempts < ?",
      cleanupLimit,
    )[0]?.n ?? 0;
  const sweep = () =>
    Effect.gen(function* () {
      yield* sync(expireAttempts);
      const due = yield* sync(() =>
        rows(
          cleanupRow,
          "SELECT * FROM veil_connection_cleanup WHERE attempts < ?",
          cleanupLimit,
        ),
      );
      for (const job of due) {
        const outcome = yield* deps.custody
          .remove(
            {
              ownerId: deps.ownerId,
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
  const enqueueLocator = (
    connectionId: string,
    locator: string,
    credential: ConnectionRow["credential"],
  ) => {
    sql.exec(
      "INSERT INTO veil_connection_cleanup (connectionId, locator, credential, attempts) VALUES (?, ?, ?, 0)",
      connectionId,
      locator,
      JSON.stringify(credential),
    );
  };
  const enqueueCleanup = (row: ConnectionRow) => {
    if (row.locator !== null)
      enqueueLocator(row.id, row.locator, row.credential);
  };
  const markReconnect = (id: string) => {
    sql.exec(
      "UPDATE veil_connections SET state = 'reconnect_required', authorityVersion = authorityVersion + 1 WHERE id = ? AND state = 'active'",
      id,
    );
    bump();
  };
  /** An attempt ends: its sealed verifier goes to cleanup and a still-pending connection is withdrawn. */
  const retireAttempt = (attempt: AttemptRow, status: string) => {
    sql.exec(
      "UPDATE veil_connection_attempts SET status = ?, pkceVerifierSealed = NULL WHERE state = ?",
      status,
      attempt.state,
    );
    const row = rows(
      connectionRow,
      "SELECT * FROM veil_connections WHERE id = ?",
      attempt.connectionId,
    )[0];
    if (row === undefined) return;
    if (attempt.pkceVerifierSealed !== null)
      enqueueLocator(row.id, attempt.pkceVerifierSealed, row.credential);
    if (row.state === "pending") {
      sql.exec(
        "UPDATE veil_connections SET state = 'revoked', authorityVersion = authorityVersion + 1 WHERE id = ?",
        row.id,
      );
      bump();
    }
  };
  const expireAttempts = () => {
    transactionSync(() => {
      for (const attempt of rows(
        attemptRow,
        "SELECT * FROM veil_connection_attempts WHERE status IN ('pending', 'consumed') AND expiresAt <= ?",
        deps.clock(),
      ))
        retireAttempt(attempt, "expired");
    });
  };

  return {
    cleanupPending,
    cleanupRetryPending,
    sweep,
    enqueueLocator,
    enqueueCleanup,
    markReconnect,
    retireAttempt,
  };
}
