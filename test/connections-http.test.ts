import { DatabaseSync } from "node:sqlite";
import { randomBytes } from "node:crypto";
import * as Effect from "effect/Effect";
import { fromNodeSqlite } from "@fungi.computer/watchdog/node-sqlite";
import { expect, it } from "vitest";
import {
  createCredentialSealer,
  createCredentialStore,
  type StoredCredential,
} from "../src/credential-store.js";
import {
  createConnections,
  createSealedCustody,
} from "../src/connections/index.js";

function fixture(now = Date.now) {
  const database = new DatabaseSync(":memory:");
  const stored = new Map<string, StoredCredential>();
  const sent: Request[] = [];
  /** Runs inside the upstream send, after the value was placed. */
  let during: (() => Promise<void>) | null = null;
  /** The upstream's answer; a plain JSON success when unset. */
  let respond: ((request: Request) => Response) | null = null;
  const secret = `sk-test-VAULTCANARY-${crypto.randomUUID()}`;
  const vault = createCredentialStore({
    storage: {
      get: (id) => Promise.resolve(stored.get(id)),
      put: (id, value) => {
        stored.set(id, value);
        return Promise.resolve();
      },
      delete: (id) => Promise.resolve(stored.delete(id)),
      list: (prefix) =>
        Promise.resolve(
          new Map([...stored].filter(([id]) => id.startsWith(prefix))),
        ),
    },
    sealer: createCredentialSealer(
      {
        activeKeyId: "test",
        keys: { test: randomBytes(32).toString("base64url") },
      },
      "test.http",
    ),
  });
  let allowed = true;
  const connections = createConnections({
    ownerId: "team",
    store: fromNodeSqlite(database),
    custody: createSealedCustody({
      vault,
      send: (request) => {
        sent.push(request);
        const step = during;
        const reply = () =>
          respond === null ? Response.json({ ok: true }) : respond(request);
        return step === null ? Promise.resolve(reply()) : step().then(reply);
      },
    }),
    authorize: (actor) => actor === "owner" && allowed,
    clock: now,
    ids: () => crypto.randomUUID(),
  });
  return {
    database,
    stored,
    sent,
    secret,
    connections,
    demote: () => {
      allowed = false;
    },
    duringSend: (step: (() => Promise<void>) | null) => {
      during = step;
    },
    upstream: (answer: ((request: Request) => Response) | null) => {
      respond = answer;
    },
  };
}

it("places an HTTP secret only for its exact subject, host, path and method", async () => {
  const h = fixture();
  try {
    const { connectionId } = await Effect.runPromise(
      h.connections.begin("owner", {
        requestId: "http",
        name: "Payments",
        surface: {
          kind: "http",
          destinations: [
            { host: "api.example.com", pathPrefix: "/v1/", methods: ["GET"] },
          ],
        },
        credential: { kind: "static", placement: "bearer" },
        secret: h.secret,
      }),
    );
    const subject = { kind: "computer", id: "work" } as const;
    const grant = await Effect.runPromise(
      h.connections.grant("owner", {
        subject,
        target: { kind: "secret", id: connectionId },
        capability: "secret.use",
        tools: "all",
      }),
    );
    const send = h.connections.egress(subject, { connectionId, ...grant });
    expect(
      (await send("https://api.example.com/v1/items", { redirect: "manual" }))
        .status,
    ).toBe(200);
    expect(h.sent[0]?.headers.get("authorization")).toBe(`Bearer ${h.secret}`);
    for (const url of [
      "https://api.example.com.evil.com/v1/items",
      "https://аpi.example.com/v1/items",
      "https://api.example.com./v1/items",
      "https://api.example.com:8443/v1/items",
      "https://127.0.0.1/v1/items",
      "https://[::1]/v1/items",
      "https://api.example.com/v10/items",
    ])
      await expect(send(url, { redirect: "manual" })).rejects.toMatchObject({
        code: "denied",
      });
    await expect(
      send("https://api.example.com/v1/items", {
        method: "POST",
        redirect: "manual",
      }),
    ).rejects.toMatchObject({ code: "denied" });
    for (const kind of ["agent", "app", "team-key"] as const)
      await expect(
        h.connections.egress({ kind, id: "work" }, { connectionId, ...grant })(
          "https://api.example.com/v1/items",
          { redirect: "manual" },
        ),
      ).rejects.toMatchObject({ code: "revoked" });
    expect(h.sent).toHaveLength(1);
    await Effect.runPromise(h.connections.revoke("owner", { connectionId }));
    await expect(
      send("https://api.example.com/v1/items", { redirect: "manual" }),
    ).rejects.toMatchObject({ code: "revoked" });
  } finally {
    h.database.close();
  }
});

it("masks a bound host's echo of the placed value, across chunks and in headers, and audits it", async () => {
  const h = fixture();
  try {
    const { connectionId } = await Effect.runPromise(
      h.connections.begin("owner", {
        requestId: "echo",
        name: "Echo",
        surface: {
          kind: "http",
          destinations: [{ host: "echo.example.com", methods: ["GET"] }],
        },
        credential: { kind: "static", placement: { header: "x-api-key" } },
        secret: h.secret,
      }),
    );
    const subject = { kind: "agent", id: "mirror" } as const;
    const grant = await Effect.runPromise(
      h.connections.grant("owner", {
        subject,
        target: { kind: "secret", id: connectionId },
        capability: "secret.use",
        tools: "all",
      }),
    );
    const send = h.connections.egress(subject, { connectionId, ...grant });
    const encoder = new TextEncoder();
    // A debug endpoint: the value raw (split across chunks), base64, JSON
    // escaped and in a response header, around bytes that are not UTF-8.
    h.upstream((request) => {
      const value = request.headers.get("x-api-key") ?? "";
      const half = value.length >> 1;
      const parts = [
        new Uint8Array([0x80, 0xff]),
        encoder.encode(`{"seen":"${value.slice(0, half)}`),
        encoder.encode(`${value.slice(half)}","b64":"${btoa(value)}"}`),
        encoder.encode(
          JSON.stringify({ hex: Buffer.from(value).toString("hex") }),
        ),
      ];
      return new Response(
        new ReadableStream({
          start(controller) {
            for (const part of parts) controller.enqueue(part);
            controller.close();
          },
        }),
        {
          headers: {
            "content-type": "application/json",
            "content-length": "999",
            "x-echo": value,
          },
        },
      );
    });
    const response = await send("https://echo.example.com/debug", {
      redirect: "manual",
    });
    const bytes = new Uint8Array(await response.arrayBuffer());
    const body = Buffer.from(bytes);
    expect([...bytes.subarray(0, 2)]).toEqual([0x80, 0xff]);
    for (const variant of [
      h.secret,
      btoa(h.secret),
      Buffer.from(h.secret).toString("hex"),
    ])
      expect(body.includes(Buffer.from(variant))).toBe(false);
    expect(body.toString("latin1")).toContain("[REDACTED]");
    expect(response.headers.get("x-echo")).toBeNull();
    expect(response.headers.get("content-length")).toBeNull();
    const audit = Effect.runSync(h.connections.audit("owner", connectionId));
    expect(audit.map((entry) => entry.outcome)).toEqual([
      "placed",
      "echo_redacted",
      "upstream_status",
    ]);
    // A response that never echoes keeps its bytes and its framing.
    h.upstream(() => new Response("plain", { headers: { "x-ok": "1" } }));
    const clean = await send("https://echo.example.com/plain", {
      redirect: "manual",
    });
    expect(await clean.text()).toBe("plain");
    expect(clean.headers.get("x-ok")).toBe("1");
  } finally {
    h.database.close();
  }
});

it("coalesces identical uses within a minute, but not at the minute boundary or across destinations", async () => {
  let now = 1_000_000;
  const h = fixture(() => now);
  try {
    const { connectionId } = await Effect.runPromise(
      h.connections.begin("owner", {
        requestId: "minute",
        name: "Minute",
        surface: {
          kind: "http",
          destinations: [
            { host: "api.example.com", methods: ["GET"] },
            { host: "files.example.com", methods: ["GET"] },
          ],
        },
        credential: { kind: "static", placement: "bearer" },
        secret: h.secret,
      }),
    );
    const subject = { kind: "computer", id: "worker" } as const;
    const grant = await Effect.runPromise(
      h.connections.grant("owner", {
        subject,
        target: { kind: "secret", id: connectionId },
        capability: "secret.use",
        tools: "all",
      }),
    );
    const send = h.connections.egress(subject, { connectionId, ...grant });
    const request = () =>
      send("https://api.example.com/items", { redirect: "manual" });
    await request();
    now += 59_999;
    await request();
    let audit = Effect.runSync(h.connections.audit("owner", connectionId));
    expect(audit.map(({ outcome, count }) => ({ outcome, count }))).toEqual([
      { outcome: "placed", count: 2 },
      { outcome: "upstream_status", count: 2 },
    ]);
    now += 1;
    await request();
    await send("https://files.example.com/items", { redirect: "manual" });
    audit = Effect.runSync(h.connections.audit("owner", connectionId));
    expect(audit.map(({ count }) => count)).toEqual([2, 2, 1, 1, 1, 1]);
    now += 90 * 24 * 60 * 60 * 1_000;
    expect(Effect.runSync(h.connections.audit("owner", connectionId))).toEqual(
      [],
    );
  } finally {
    h.database.close();
  }
});

it("audits placement and refusals without retaining request credentials, paths or queries", async () => {
  const h = fixture();
  try {
    const { connectionId } = await Effect.runPromise(
      h.connections.begin("owner", {
        requestId: "audit",
        name: "Audit",
        surface: {
          kind: "http",
          destinations: [{ host: "api.example.com", methods: ["GET"] }],
        },
        credential: { kind: "static", placement: "bearer" },
        secret: h.secret,
      }),
    );
    const subject = { kind: "agent", id: "worker" } as const;
    const grant = await Effect.runPromise(
      h.connections.grant("owner", {
        subject,
        target: { kind: "secret", id: connectionId },
        capability: "secret.use",
        tools: "all",
      }),
    );
    const send = h.connections.egress(subject, { connectionId, ...grant });
    await send(`https://api.example.com/${h.secret}?key=${h.secret}`, {
      redirect: "manual",
    });
    await expect(
      send(`https://evil.example/${h.secret}`, { redirect: "manual" }),
    ).rejects.toMatchObject({ code: "denied" });
    await Effect.runPromise(
      h.connections.ungrant("owner", {
        subject,
        target: { kind: "secret", id: connectionId },
        capability: "secret.use",
      }),
    );
    await expect(
      send("https://api.example.com/", { redirect: "manual" }),
    ).rejects.toMatchObject({ code: "revoked" });
    const audit = Effect.runSync(h.connections.audit("owner", connectionId));
    expect(audit.map((entry) => entry.outcome)).toEqual([
      "placed",
      "upstream_status",
      "refused_destination",
      "refused_grant",
    ]);
    expect(audit[0]).toMatchObject({
      subject,
      grantor: "owner",
      host: "api.example.com",
      method: "GET",
    });
    expect(JSON.stringify(audit)).not.toContain(h.secret);
    // Scan every SQLite cell, including receipts and audit, plus all sealed records.
    const tables = h.database
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all();
    for (const name of tables.map((table) => String(table.name))) {
      const cells = h.database
        .prepare(`SELECT * FROM "${name.replaceAll('"', '""')}"`)
        .all();
      expect(
        Buffer.from(JSON.stringify(cells)).includes(Buffer.from(h.secret)),
      ).toBe(false);
    }
    expect(
      Buffer.from(JSON.stringify([...h.stored])).includes(
        Buffer.from(h.secret),
      ),
    ).toBe(false);
  } finally {
    h.database.close();
  }
});

it("places Basic credentials only at send and rechecks a demoted grantor", async () => {
  const h = fixture();
  try {
    const { connectionId } = await Effect.runPromise(
      h.connections.begin("owner", {
        requestId: "basic",
        name: "Basic",
        surface: {
          kind: "http",
          destinations: [{ host: "api.example.com", methods: ["GET"] }],
        },
        credential: { kind: "static", placement: "basic" },
        secret: `user:${h.secret}`,
      }),
    );
    const subject = { kind: "team-key", id: "work" } as const;
    const grant = await Effect.runPromise(
      h.connections.grant("owner", {
        subject,
        target: { kind: "secret", id: connectionId },
        capability: "secret.use",
        tools: "all",
      }),
    );
    const send = h.connections.egress(subject, { connectionId, ...grant });
    await send("https://api.example.com/", { redirect: "manual" });
    expect(h.sent[0]?.headers.get("authorization")).toBe(
      `Basic ${btoa(`user:${h.secret}`)}`,
    );
    h.demote();
    await expect(
      send("https://api.example.com/", { redirect: "manual" }),
    ).rejects.toMatchObject({ code: "denied" });
    expect(h.sent).toHaveLength(1);
    expect(JSON.stringify([...h.stored])).not.toContain(h.secret);
  } finally {
    h.database.close();
  }
});

/** One secret with a live Computer grant, and the SQLite audit table it writes. */
async function bound(h: ReturnType<typeof fixture>, name = "Cap") {
  const { connectionId } = await Effect.runPromise(
    h.connections.begin("owner", {
      requestId: `cap-${name}`,
      name,
      surface: {
        kind: "http",
        destinations: [{ host: "api.example.com", methods: ["GET"] }],
      },
      credential: { kind: "static", placement: "bearer" },
      secret: h.secret,
    }),
  );
  const subject = { kind: "computer", id: "worker" } as const;
  const grant = await Effect.runPromise(
    h.connections.grant("owner", {
      subject,
      target: { kind: "secret", id: connectionId },
      capability: "secret.use",
      tools: "all",
    }),
  );
  const send = h.connections.egress(subject, { connectionId, ...grant });
  return {
    connectionId,
    subject,
    ungrant: () =>
      Effect.runPromise(
        h.connections.ungrant("owner", {
          subject,
          target: { kind: "secret", id: connectionId },
          capability: "secret.use",
        }),
      ),
    ok: () => send("https://api.example.com/items", { redirect: "manual" }),
    refused: () => send("https://evil.example/items", { redirect: "manual" }),
    rows: () =>
      Number(
        h.database
          .prepare("SELECT COUNT(*) AS n FROM veil_connection_usage")
          .get()?.n,
      ),
    // Capacity seeding copies a real row under distinct coalescing keys.
    copy: (sequence: number, times: number) =>
      h.database
        .prepare(
          `
      INSERT INTO veil_connection_usage (connectionId, coalesceKey, firstAt, lastAt, uses, protected, record)
      WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
      SELECT connectionId, coalesceKey || '#' || i, firstAt, lastAt, uses, protected, record
      FROM n, veil_connection_usage WHERE sequence = ?`,
        )
        .run(times, sequence),
  };
}

it("caps an owner at 250,000 rows, pruning the oldest unprotected use and keeping young refusals", async () => {
  let now = 5_000_000;
  const h = fixture(() => now);
  try {
    const s = await bound(h);
    await expect(s.refused()).rejects.toMatchObject({ code: "denied" }); // sequence 1, protected
    now += 1;
    await s.ok(); // sequences 2 (placed) and 3 (upstream_status)
    s.copy(2, 249_997);
    expect(s.rows()).toBe(250_000);
    now += 2 * 60_000;
    await s.ok();
    expect(s.rows()).toBe(250_000);
    const kept = h.database
      .prepare("SELECT sequence FROM veil_connection_usage WHERE sequence <= 3")
      .all();
    expect(kept.map((row) => row.sequence)).toEqual([1]);
    expect(
      Effect.runSync(h.connections.audit("owner", s.connectionId)).at(-1)
        ?.outcome,
    ).toBe("upstream_status");
  } finally {
    h.database.close();
  }
});

it("lets young refusals hold an owner above the cap until they reach 90 days", async () => {
  let now = 7_000_000;
  const h = fixture(() => now);
  try {
    const s = await bound(h);
    const born = now;
    await expect(s.refused()).rejects.toMatchObject({ code: "denied" });
    s.copy(1, 249_999);
    expect(s.rows()).toBe(250_000);
    now = born + 90 * 24 * 60 * 60 * 1_000 - 1;
    // Young refusals are never pruned, so the use is still audited above the
    // cap; only the use's own earlier unprotected row gives way to its result.
    expect((await s.ok()).status).toBe(200);
    expect(s.rows()).toBe(250_001);
    expect(
      Effect.runSync(h.connections.audit("owner", s.connectionId)).at(-1)
        ?.outcome,
    ).toBe("upstream_status");
    now += 1;
    await expect(s.refused()).rejects.toMatchObject({ code: "denied" });
    // The refusals reached 90 days and aged out through retention alone.
    expect(s.rows()).toBe(2);
  } finally {
    h.database.close();
  }
});

it("refuses a use whose audit row cannot be written, before anything is sent", async () => {
  const h = fixture();
  try {
    const s = await bound(h);
    h.database.exec("DROP TABLE veil_connection_usage");
    await expect(s.ok()).rejects.toMatchObject({ code: "unavailable" });
    expect(h.sent).toHaveLength(0);
  } finally {
    h.database.close();
  }
});

it("binds a secret to at most eight destination rules", async () => {
  const h = fixture();
  try {
    const rules = (n: number) =>
      Array.from({ length: n }, (_, i) => ({
        host: `api${String(i)}.example.com`,
        methods: ["GET" as const],
      }));
    const begin = (n: number) =>
      Effect.runPromise(
        Effect.result(
          h.connections.begin("owner", {
            requestId: `rules-${String(n)}`,
            name: `Rules${String(n)}`,
            surface: { kind: "http", destinations: rules(n) },
            credential: { kind: "static", placement: "bearer" },
            secret: h.secret,
          }),
        ),
      );
    expect((await begin(8))._tag).toBe("Success");
    const nine = await begin(9);
    expect(nine._tag === "Failure" && nine.failure.code).toBe("invalid_input");
  } finally {
    h.database.close();
  }
});

it("refuses to grant secret use to an App: the Vault adds no App power", async () => {
  const h = fixture();
  try {
    const s = await bound(h);
    const refused = await Effect.runPromise(
      Effect.result(
        h.connections.grant("owner", {
          subject: { kind: "app", id: "app-a" },
          target: { kind: "secret", id: s.connectionId },
          capability: "secret.use",
          tools: "all",
        }),
      ),
    );
    expect(refused._tag === "Failure" && refused.failure.code).toBe(
      "unsupported",
    );
    const view = Effect.runSync(h.connections.list("owner")).find(
      (row) => row.connectionId === s.connectionId,
    );
    expect(view?.grants.map((grant) => grant.subject.kind)).toEqual([
      "computer",
    ]);
  } finally {
    h.database.close();
  }
});

it("audits a revoke seen after the send, and a custodian failure, as protected refusals that outlive pruning", async () => {
  let now = 9_000_000;
  const h = fixture(() => now);
  try {
    const s = await bound(h);
    // The grant ends while the request is in flight.
    h.duringSend(() => s.ungrant());
    await expect(s.ok()).rejects.toMatchObject({ code: "revoked" });
    h.duringSend(() => Promise.reject(new Error("custodian down")));
    const second = await bound(h, "Second");
    now += 1;
    await expect(second.ok()).rejects.toMatchObject({ code: "unavailable" });
    h.duringSend(null);
    const refusals = (id: string) =>
      Effect.runSync(h.connections.audit("owner", id))
        .filter((row) => row.outcome !== "placed")
        .map((row) => row.outcome);
    expect(refusals(s.connectionId)).toEqual(["refused_grant"]);
    expect(refusals(second.connectionId)).toEqual(["refused_grant"]);
    const protectedRows = () =>
      Number(
        h.database
          .prepare(
            "SELECT COUNT(*) AS n FROM veil_connection_usage WHERE protected = 1",
          )
          .get()?.n,
      );
    expect(protectedRows()).toBe(2);
    // Fill the owner with unprotected rows, then push one more use through.
    const placed = h.database
      .prepare(
        "SELECT sequence FROM veil_connection_usage WHERE protected = 0 ORDER BY sequence LIMIT 1",
      )
      .get()?.sequence;
    second.copy(Number(placed), 250_000 - second.rows());
    now += 2 * 60_000;
    const third = await bound(h, "Third");
    await third.ok();
    expect(protectedRows()).toBe(2);
    // The listing shows only the newest rows, so read the survivors directly.
    expect(
      h.database
        .prepare(
          "SELECT connectionId, json_extract(record, '$.outcome') AS outcome FROM veil_connection_usage WHERE protected = 1 ORDER BY sequence",
        )
        .all()
        .map((row) => [row.connectionId, row.outcome]),
    ).toEqual([
      [s.connectionId, "refused_grant"],
      [second.connectionId, "refused_grant"],
    ]);
  } finally {
    h.database.close();
  }
});

it("strips routing headers so a placed value goes only where its URL says", async () => {
  const h = fixture();
  try {
    const { connectionId } = await Effect.runPromise(
      h.connections.begin("owner", {
        requestId: "routing",
        name: "Payments",
        surface: {
          kind: "http",
          destinations: [
            {
              host: "api.example.com",
              pathPrefix: "/v1/",
              methods: ["GET", "POST"],
            },
          ],
        },
        credential: { kind: "static", placement: "bearer" },
        secret: h.secret,
      }),
    );
    const subject = { kind: "computer", id: "work" } as const;
    const grant = await Effect.runPromise(
      h.connections.grant("owner", {
        subject,
        target: { kind: "secret", id: connectionId },
        capability: "secret.use",
        tools: "all",
      }),
    );
    const send = h.connections.egress(subject, { connectionId, ...grant });
    const routing = {
      host: "evil.example",
      "x-forwarded-host": "evil.example",
      "X-Forwarded-For": "10.0.0.1",
      forwarded: "host=evil.example",
      via: "1.1 evil.example",
      "x-original-host": "evil.example",
      "x-real-ip": "10.0.0.1",
      accept: "application/json",
    };
    expect(
      (
        await send("https://api.example.com/v1/items", {
          redirect: "manual",
          headers: routing,
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await send("https://api.example.com/v1/items", {
          method: "POST",
          redirect: "manual",
          headers: { ...routing, "content-type": "application/json" },
          body: "{}",
        })
      ).status,
    ).toBe(200);
    expect(h.sent.map((request) => [...request.headers.keys()].sort())).toEqual(
      [
        ["accept", "authorization"],
        ["accept", "authorization", "content-type"],
      ],
    );
    expect(h.sent.map((request) => new URL(request.url).host)).toEqual([
      "api.example.com",
      "api.example.com",
    ]);
  } finally {
    h.database.close();
  }
});
