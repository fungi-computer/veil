import { DatabaseSync } from "node:sqlite";
import * as Effect from "effect/Effect";
import { fromNodeSqlite } from "@fungi.computer/watchdog/node-sqlite";
import { expect, it } from "vitest";
import { createConnections } from "../src/connections/index.js";

it("reopens every stored agent grant as a subject grant without widening authority", async () => {
  const database = new DatabaseSync(":memory:");
  try {
    // The real pre-S2 store, including an inactive grant and a narrowed tool set.
    database.exec(`
      CREATE TABLE veil_connections (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, surface TEXT NOT NULL,
        credential TEXT NOT NULL, locator TEXT, state TEXT NOT NULL,
        authorityVersion INTEGER NOT NULL, version INTEGER NOT NULL) STRICT;
      CREATE TABLE veil_connection_grants (
        connectionId TEXT NOT NULL, agentId TEXT NOT NULL, tools TEXT NOT NULL,
        grantor TEXT NOT NULL, version INTEGER NOT NULL, active INTEGER NOT NULL,
        PRIMARY KEY (connectionId, agentId)) STRICT;
      INSERT INTO veil_connections VALUES (
        'notes', 'Notes',
        '{"kind":"mcp","url":"https://notes.example.com/mcp","table":null}',
        '{"kind":"none"}', NULL, 'active', 3, 2);
      INSERT INTO veil_connection_grants VALUES
        ('notes', 'reader', '["read"]', 'owner', 7, 1),
        ('notes', 'retired', '"all"', 'owner', 9, 0);
    `);
    let sends = 0;
    const open = () =>
      createConnections({
        ownerId: "team",
        store: fromNodeSqlite(database),
        authorize: (actor) => actor === "owner",
        custody: {
          put: () => Effect.succeed("unused"),
          remove: () => Effect.succeed("absent"),
          inject: () =>
            Effect.sync(() => {
              sends += 1;
              return Response.json({});
            }),
        },
        clock: () => 1_000,
        ids: () => crypto.randomUUID(),
      });
    const connections = open();
    // Every stored row, the inactive retired one included, keeps every field:
    // only its key columns move into the subject grammar.
    expect(
      database
        .prepare(
          "SELECT target, subject, capability, tools, grantor, version, active FROM veil_connection_grants ORDER BY subject",
        )
        .all(),
    ).toEqual([
      {
        target: '{"kind":"connection","id":"notes"}',
        subject: '{"kind":"agent","id":"reader"}',
        capability: "connector.call",
        tools: '["read"]',
        grantor: "owner",
        version: 7,
        active: 1,
      },
      {
        target: '{"kind":"connection","id":"notes"}',
        subject: '{"kind":"agent","id":"retired"}',
        capability: "connector.call",
        tools: '"all"',
        grantor: "owner",
        version: 9,
        active: 0,
      },
    ]);
    expect(Effect.runSync(connections.list("owner"))[0]?.grants).toEqual([
      {
        subject: { kind: "agent", id: "reader" },
        target: { kind: "connection", id: "notes" },
        capability: "connector.call",
        tools: ["read"],
        grantor: "owner",
        version: 7,
      },
    ]);
    const ref = { connectionId: "notes", grantVersion: 7 };
    const request = () =>
      new Request("https://notes.example.com/mcp", {
        redirect: "manual",
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "read" },
        }),
      });
    await connections.egress({ kind: "agent", id: "reader" }, ref)(request());
    await expect(
      connections.egress({ kind: "computer", id: "reader" }, ref)(request()),
    ).rejects.toMatchObject({ code: "revoked" });
    await expect(
      connections.egress(
        { kind: "agent", id: "retired" },
        { ...ref, grantVersion: 9 },
      )(request()),
    ).rejects.toMatchObject({ code: "revoked" });
    await open().egress({ kind: "agent", id: "reader" }, ref)(request());
    expect(sends).toBe(2);
    // Old writers cannot restore the superseded representation after migration.
    expect(() =>
      database
        .prepare(
          "INSERT INTO veil_connection_grants (connectionId, agentId, tools, grantor, version, active) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .run("notes", "other", '"all"', "owner", 1, 1),
    ).toThrow();
  } finally {
    database.close();
  }
});
