import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { normalizeOpenApi } from "@fungi.computer/forage/openapi";
import { fromNodeSqlite } from "@fungi.computer/watchdog/node-sqlite";
import * as Effect from "effect/Effect";
import {
  ConnectionsError,
  createConnections,
  type CustodyAdapter,
} from "../../src/connections/index.js";

export const repository = {
  id: 42,
  full_name: "fixture/selected",
  private: true,
  default_branch: "main",
};

/** Only external custody and its upstream vary. SQLite and the caller are real. */
export type CallerSubject = Readonly<{
  custody: CustodyAdapter;
  baseUrl: string;
  secret: string;
  requests: () => number;
  pause: () => Promise<void>;
  resume: () => Promise<void>;
  providerStatus: (status: number) => void;
}>;

const run = <A>(effect: Effect.Effect<A, ConnectionsError>) =>
  Effect.runPromise(effect);
const code = (effect: Effect.Effect<unknown, ConnectionsError>) =>
  run(
    Effect.match(effect, {
      onSuccess: () => "ok",
      onFailure: (error) => error.code,
    }),
  );

/** Same substantive sequence for deterministic custody and the pinned native server. */
export async function proveConnectionsCaller(subject: CallerSubject) {
  const directory = await mkdtemp(join(tmpdir(), "veil-caller-"));
  const path = join(directory, "team.sqlite");
  let database = new DatabaseSync(path);
  let allowed = true;
  let tick = 0;
  let loseDeleteAcknowledgement = false;
  let successfulDeletes = 0;
  let absentDeletes = 0;
  // Fault at the acknowledgement boundary, after the actual custodian deletion.
  const custody: CustodyAdapter = {
    ...subject.custody,
    remove: (address, locator) =>
      subject.custody.remove(address, locator).pipe(
        Effect.flatMap((result) => {
          if (result === "deleted") successfulDeletes += 1;
          else absentDeletes += 1;
          if (loseDeleteAcknowledgement) {
            loseDeleteAcknowledgement = false;
            return Effect.fail(new ConnectionsError("unavailable"));
          }
          return Effect.succeed(result);
        }),
      ),
  };
  const open = (ownerId = "team-a", store = database) =>
    createConnections({
      ownerId,
      store: fromNodeSqlite(store),
      custody,
      authorize: (actor) => actor === "owner" && allowed,
      ids: () => `caller-${String(++tick)}`,
      clock: () => Date.now(),
      egressPolicy: {
        extraPorts: [Number(new URL(subject.baseUrl).port) || 443],
      },
    });
  let connections = open();
  const reopen = () => {
    database.close();
    database = new DatabaseSync(path);
    connections = open();
  };
  const table = (
    await normalizeOpenApi(
      JSON.stringify({
        openapi: "3.0.0",
        info: { title: "Selected repository", version: "1" },
        servers: [{ url: subject.baseUrl }],
        paths: {
          "/repos/fixture/selected": {
            get: {
              operationId: "readRepository",
              responses: {
                "200": {
                  description: "Repository metadata",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          id: { type: "integer" },
                          full_name: { type: "string" },
                          private: { type: "boolean" },
                          default_branch: { type: "string" },
                        },
                        required: [
                          "id",
                          "full_name",
                          "private",
                          "default_branch",
                        ],
                        additionalProperties: false,
                      },
                    },
                  },
                },
              },
            },
          },
        },
      }),
    )
  ).operations.filter((operation) => operation.status === "supported");
  const draft = {
    requestId: "connect-repository",
    name: "Repository",
    surface: { kind: "openapi", baseUrl: subject.baseUrl, table },
    credential: { kind: "static", placement: "bearer" },
    secret: subject.secret,
  } as const;
  const publicValues: unknown[] = [];
  try {
    const connected = await run(connections.begin("owner", draft));
    publicValues.push(connected);
    // Lose the begin response, close the actual SQLite handle, retry the same intent.
    reopen();
    assert.deepEqual(await run(connections.begin("owner", draft)), connected);
    assert.equal((await run(connections.list("owner"))).length, 1);
    const grant = await run(
      connections.grant("owner", {
        target: { kind: "connection", id: connected.connectionId },
        subject: { kind: "agent", id: "agent-a" },
        capability: "connector.call",
        tools: ["readRepository"],
      }),
    );
    const ref = { connectionId: connected.connectionId, ...grant };
    const input = { operation: "readRepository", input: {} };
    const call = () =>
      connections.call({ kind: "agent", id: "agent-a" }, ref, input);
    publicValues.push(
      await run(connections.list("owner")),
      await run(connections.projection({ kind: "agent", id: "agent-a" })),
    );
    assert.equal(
      (await readFile(path)).includes(Buffer.from(subject.secret)),
      false,
      "active Team storage contains no credential",
    );
    publicValues.push(await run(call()));
    assert.deepEqual(publicValues.at(-1), repository);
    assert.equal(subject.requests(), 1);
    reopen();
    assert.deepEqual(await run(call()), repository);
    assert.equal(subject.requests(), 2);

    const beforeDenials = subject.requests();
    await run(
      connections.ungrant("owner", {
        target: { kind: "connection", id: connected.connectionId },
        subject: { kind: "agent", id: "agent-a" },
        capability: "connector.call",
      }),
    );
    assert.equal(await code(call()), "revoked");
    const renewed = await run(
      connections.grant("owner", {
        target: { kind: "connection", id: connected.connectionId },
        subject: { kind: "agent", id: "agent-a" },
        capability: "connector.call",
        tools: ["readRepository"],
      }),
    );
    ref.grantVersion = renewed.grantVersion;

    assert.equal(
      await code(
        connections.call({ kind: "agent", id: "agent-b" }, ref, input),
      ),
      "revoked",
    );
    assert.equal(
      await code(
        connections.call(
          { kind: "agent", id: "agent-a" },
          { ...ref, grantVersion: ref.grantVersion + 1 },
          input,
        ),
      ),
      "revoked",
    );
    assert.equal(
      await code(
        connections.call({ kind: "agent", id: "agent-a" }, ref, {
          operation: "readOtherRepository",
          input: {},
        }),
      ),
      "denied",
    );
    allowed = false;
    assert.equal(await code(call()), "denied");
    allowed = true;
    const otherDatabase = new DatabaseSync(":memory:");
    try {
      assert.notEqual(
        await code(
          open("team-b", otherDatabase).call(
            { kind: "agent", id: "agent-a" },
            ref,
            input,
          ),
        ),
        "ok",
      );
    } finally {
      otherDatabase.close();
    }
    assert.equal(subject.requests(), beforeDenials);

    const allTools = await run(
      connections.grant("owner", {
        target: { kind: "connection", id: connected.connectionId },
        subject: { kind: "agent", id: "agent-a" },
        capability: "connector.call",
        tools: "all",
      }),
    );
    ref.grantVersion = allTools.grantVersion;
    const aborted = new AbortController();
    aborted.abort();
    await assert.rejects(
      connections.egress(
        { kind: "agent", id: "agent-a" },
        ref,
      )(
        new Request(`${subject.baseUrl}/repos/fixture/selected`, {
          signal: aborted.signal,
          redirect: "manual",
        }),
      ),
      { name: "ConnectionsError", code: "unavailable" },
    );
    assert.equal(subject.requests(), beforeDenials);
    subject.providerStatus(503);
    assert.equal(await code(call()), "invalid_response");
    subject.providerStatus(200);
    assert.equal((await run(connections.list("owner")))[0]?.state, "active");
    await subject.pause();
    assert.equal(await code(call()), "unavailable");
    assert.equal((await run(connections.list("owner")))[0]?.state, "active");

    const beforeDisconnect = subject.requests();
    await run(
      connections.revoke("owner", { connectionId: connected.connectionId }),
    );
    assert.equal(connections.cleanupPending(), 1);
    assert.equal(successfulDeletes, 0);
    reopen();
    assert.notEqual(await code(call()), "ok");
    assert.equal(subject.requests(), beforeDisconnect);
    assert.equal((await run(connections.list("owner")))[0]?.state, "revoked");
    await subject.resume();
    loseDeleteAcknowledgement = true;
    await run(connections.sweep());
    assert.equal(successfulDeletes, 1);
    assert.equal(connections.cleanupPending(), 1);
    reopen();
    await run(connections.sweep());
    assert.equal(absentDeletes, 1);
    assert.equal(connections.cleanupPending(), 0);
    assert.notEqual(await code(call()), "ok");
    assert.equal(subject.requests(), beforeDisconnect);
    publicValues.push(
      await run(connections.list("owner")),
      await run(connections.projection({ kind: "agent", id: "agent-a" })),
    );
    assert.equal(
      JSON.stringify(publicValues).includes(subject.secret),
      false,
      "public results contain no credential",
    );
    database.close();
    assert.equal(
      (await readFile(path)).includes(Buffer.from(subject.secret)),
      false,
      "Team storage contains no credential",
    );
  } finally {
    if (database.isOpen) database.close();
    await subject.resume();
    await rm(directory, { recursive: true, force: true });
  }
}
