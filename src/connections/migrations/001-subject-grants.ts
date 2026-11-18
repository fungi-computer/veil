import * as Schema from "effect/Schema";
import type { SqlStore } from "../contract.js";

/**
 * Connection owners run this before opening the core, on Hub and Oyster alike.
 * SQLite owns the atomic conversion; there is no runtime old-shape reader.
 */
export function migrateSubjectGrants(store: SqlStore): void {
  store.transactionSync(() => {
    const { sql } = store;
    sql.exec(`CREATE TABLE IF NOT EXISTS veil_connection_migrations (
      version INTEGER PRIMARY KEY) STRICT`);
    const applied = sql
      .exec("SELECT version FROM veil_connection_migrations WHERE version = 1")
      .toArray();
    if (applied.length !== 0) return;
    const existing = sql
      .exec(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'veil_connection_grants'",
      )
      .toArray()
      .map((row) =>
        Schema.decodeUnknownSync(Schema.Struct({ name: Schema.String }))(row),
      );
    if (existing.length !== 0)
      sql.exec(
        "ALTER TABLE veil_connection_grants RENAME TO veil_connection_grants_001",
      );
    sql.exec(`CREATE TABLE veil_connection_grants (
      target TEXT NOT NULL, subject TEXT NOT NULL, capability TEXT NOT NULL,
      tools TEXT NOT NULL, grantor TEXT NOT NULL, version INTEGER NOT NULL,
      active INTEGER NOT NULL, PRIMARY KEY (target, subject, capability)) STRICT`);
    if (existing.length !== 0) {
      sql.exec(`INSERT INTO veil_connection_grants
        SELECT json_object('kind', 'connection', 'id', connectionId),
          json_object('kind', 'agent', 'id', agentId), 'connector.call',
          tools, grantor, version, active FROM veil_connection_grants_001`);
      sql.exec("DROP TABLE veil_connection_grants_001");
    }
    sql.exec("INSERT INTO veil_connection_migrations VALUES (1)");
  });
}
