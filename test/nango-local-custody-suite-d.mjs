/* global console, setTimeout, fetch, AbortController, Request, Headers */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";
import { networkInterfaces } from "node:os";
import process from "node:process";
import * as Effect from "effect/Effect";
import { createNangoCustody } from "../src/connections/nango.js";

import { createNangoModelKeyCustodian } from "../src/nango-model-keys.js";
import { VeilError } from "../src/index.js";

// Auth v1 gate section 5 / issue auth-v1-security-gate-05 "suite D": the same
// custodian laws the fake suite proves, run here against a REAL, isolated,
// disposable native Nango server (the pinned self-hosted image) instead of a
// mocked fetch. This starts its own Postgres and Nango containers, talks to
// them over real HTTP with the actual `createNangoModelKeyCustodian` adapter,
// and tears everything down. It never touches the host's `fungi-nango`
// container (that one is production/shared and is never read or targeted by
// this script), never prints a credential value, and only ever carries
// synthetic, locally generated secrets that exist nowhere else.
//
// Run: node_modules/.bin/tsx packages/veil/test/nango-local-custody-suite-d.mjs
// Requires: docker, network access to pull the pinned image once.

const IMAGE =
  "nangohq/nango-server:hosted-7c00d83c6d6e6155a2e49a76061d0aa4d6bd464b";
const PINNED_DIGEST =
  "sha256:cc2419c46221e6b4f6fa72f08a11bf69632cc7ebacc0658a44eb745927d9046a";

const run = randomUUID().slice(0, 8);
const pgName = `veil-suite-d-pg-${run}`;
const restorePgName = `veil-suite-d-pg-restore-${run}`;
const restoreNangoName = `veil-suite-d-nango-restore-${run}`;
const nangoName = `veil-suite-d-nango-${run}`;
const integrationKey = `veil-suite-d-${run}`;
const connectionLocator = `suite-d-${run}`;
const syntheticApiKey = `synthetic-suite-d-secret-${run}`;

const seenSecretLeaks = [];
const cleanupFailures = [];
/** Record canary exposure without printing its value or the captured bytes. */
function assertNoLeak(label, haystack) {
  if (haystack.includes(syntheticApiKey)) seenSecretLeaks.push(label);
}

function docker(args, options = {}) {
  try {
    return execFileSync("docker", args, {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      ...options,
    }).trim();
  } catch {
    // Child errors contain argv (including generated keys) and captured output.
    throw new Error(`disposable Docker ${args[0]} failed`);
  }
}

function dockerLogsSince(name, since) {
  const result = spawnSync("docker", ["logs", "--since", since, name], {
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
  });
  if (result.status !== 0) throw new Error("disposable Docker log read failed");
  // Docker preserves the container's stdout/stderr distinction. Scan both.
  return result.stdout + result.stderr;
}

async function waitFor(check, { timeoutMs = 30_000, intervalMs = 500 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await check()) return;
    if (Date.now() > deadline) throw new Error("timed out waiting");
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

/** Starts one disposable Nango container against one disposable Postgres. The
 * restore rehearsal reuses it with the original key and a restored database. */
function startNango(name, pgIp, pgPassword, encryptionKey) {
  docker([
    "run",
    "-d",
    "--name",
    name,
    "-p",
    "127.0.0.1:0:8080",
    "-e",
    `NANGO_DB_HOST=${pgIp}`,
    "-e",
    "NANGO_DB_PORT=5432",
    "-e",
    "NANGO_DB_USER=nango",
    "-e",
    `NANGO_DB_PASSWORD=${pgPassword}`,
    "-e",
    "NANGO_DB_NAME=nango",
    "-e",
    `NANGO_ENCRYPTION_KEY=${encryptionKey}`,
    "-e",
    "SERVER_PORT=8080",
    "-e",
    "NANGO_SERVER_PORT=8080",
    "-e",
    "NANGO_LOGS_ENABLED=false",
    "-e",
    "NANGO_TELEMETRY=false",
    // Isolated test-only egress posture: this disposable instance's proxy is
    // allowed to reach the private test upstream. The denylist override is
    // emptied for THIS container only; production Nango is never touched.
    "-e",
    "NANGO_PROXY_BASE_URL_OVERRIDE_ENABLED=true",
    "-e",
    "NANGO_PROXY_BASE_URL_OVERRIDE_DENYLIST=[]",
    "-e",
    'NANGO_OUTBOUND_URL_POLICY={"blockPrivateIps":false}',
    IMAGE,
  ]);
  const hostPort = docker([
    "inspect",
    "-f",
    '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}',
    name,
  ]);
  return `http://127.0.0.1:${hostPort}`;
}

async function waitForNangoHealth(serverUrl) {
  await waitFor(async () => {
    try {
      const response = await fetch(`${serverUrl}/health`);
      return response.ok;
    } catch {
      return false;
    }
  });
}

async function waitForPostgres(name) {
  await waitFor(() => {
    try {
      docker(["exec", name, "pg_isready", "-U", "nango"]);
      return true;
    } catch {
      return false;
    }
  });
}

function containerIp(name) {
  return docker([
    "inspect",
    "-f",
    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
    name,
  ]);
}

function startPostgres(name, pgPassword) {
  docker([
    "run",
    "-d",
    "--name",
    name,
    "-e",
    "POSTGRES_DB=nango",
    "-e",
    "POSTGRES_USER=nango",
    "-e",
    `POSTGRES_PASSWORD=${pgPassword}`,
    "postgres:16-alpine",
  ]);
}

function removeQuietly(name, operation) {
  try {
    docker(["rm", "-f", name]);
  } catch (cause) {
    cleanupFailures.push({ operation, cause });
  }
}

/** Backup and key-restore rehearsal. Dumps the live store as plain SQL (so a
 * canary scan is meaningful; a compressed dump would hide plaintext), restores
 * it into a fresh Postgres, starts a fresh Nango with the ORIGINAL key, and
 * proves the sealed connection decrypts and injects the same secret. Returns
 * the backup text so the caller can scan it. */
async function rehearseBackupRestore({
  pgPassword,
  encryptionKey,
  devKey,
  access,
  baseUrl,
  observations,
}) {
  const backup = docker(
    ["exec", pgName, "pg_dump", "-U", "nango", "-d", "nango", "--format=plain"],
    { encoding: "utf8", maxBuffer: 512 * 1024 * 1024 },
  );
  assert.ok(
    backup.includes(connectionLocator),
    "the backup must contain the sealed connection row, or the canary scan proves nothing",
  );
  assert.ok(
    !backup.includes(syntheticApiKey),
    "the backup must hold the credential only encrypted",
  );
  console.log(JSON.stringify({ stage: "backup-taken", bytes: backup.length }));

  startPostgres(restorePgName, pgPassword);
  await waitForPostgres(restorePgName);
  // Restore runs against a database that Nango has never seen.
  docker(
    [
      "exec",
      "-i",
      restorePgName,
      "psql",
      "-U",
      "nango",
      "-d",
      "nango",
      "-v",
      "ON_ERROR_STOP=1",
      "-q",
    ],
    { input: backup, encoding: "utf8", maxBuffer: 512 * 1024 * 1024 },
  );
  const restoreUrl = startNango(
    restoreNangoName,
    containerIp(restorePgName),
    pgPassword,
    encryptionKey,
  );
  try {
    await waitForNangoHealth(restoreUrl);
    const restoredCustodian = createNangoModelKeyCustodian({
      serverUrl: restoreUrl,
      apiKey: devKey,
      integrations: { "openai-compatible": integrationKey },
    });
    const before = observations.length;
    const restored = await restoredCustodian.send(
      access,
      new Request(`${baseUrl}/v1/models`, { method: "GET" }),
    );
    assert.equal(restored.status, 200);
    await restored.text();
    assert.equal(observations.length, before + 1);
    assert.ok(
      observations[before].authorization === `Bearer ${syntheticApiKey}`,
      "the restored store with the original key must decrypt to the same secret",
    );
    console.log(
      JSON.stringify({
        stage: "restore-decrypts-same-secret",
        restoredSecretMatches: true,
      }),
    );
  } finally {
    try {
      assertNoLeak(
        "restored-nango-container-logs",
        dockerLogsSince(restoreNangoName, "0"),
      );
    } catch (cause) {
      cleanupFailures.push({
        operation: "read restored Nango container logs",
        cause,
      });
    }
  }
  return backup;
}

// Exercise the current optional Connections adapter too. The historical model-key
// adapter above is a separate consumer and does not establish this contract.
async function proveConnectionsCustody(
  serverUrl,
  devKey,
  baseUrl,
  observations,
) {
  const custody = createNangoCustody({
    serverUrl,
    apiKey: devKey,
    webhookSigningKey: "unused-local-signing-key",
    staticIntegrationId: integrationKey,
    connectBaseUrl: serverUrl,
    publicApiUrl: serverUrl,
  });
  const address = {
    ownerId: `team-${run}`,
    connectionId: `connections-${run}`,
    credential: { kind: "static", placement: "bearer" },
  };
  const locator = await Effect.runPromise(
    custody.put(address, syntheticApiKey),
  );
  console.log(JSON.stringify({ stage: "connections-sealed" }));
  assert.ok(!locator.includes(syntheticApiKey), "locator must be secret-free");
  const before = observations.length;
  const response = await Effect.runPromise(
    custody.inject(address, locator, new Request(`${baseUrl}/v1/models`)),
  );
  assert.equal(response.status, 200);
  await response.text();
  console.log(
    JSON.stringify({ stage: "connections-egress", status: response.status }),
  );
  assert.equal(observations.length, before + 1);
  assert.ok(
    observations[before].authorization === `Bearer ${syntheticApiKey}`,
    "Connections must inject the sealed credential at final egress",
  );
  assert.equal(
    await Effect.runPromise(custody.remove(address, locator)),
    "deleted",
  );
  console.log(JSON.stringify({ stage: "connections-removed" }));
  assert.equal(
    await Effect.runPromise(custody.remove(address, locator)),
    "absent",
  );
  console.log(JSON.stringify({ stage: "connections-remove-replayed" }));
  const denied = await Effect.runPromise(
    custody.inject(address, locator, new Request(`${baseUrl}/v1/models`)).pipe(
      Effect.matchEffect({
        onSuccess: (response) =>
          Effect.promise(async () => {
            await response.body?.cancel();
            return `http_${response.status}`;
          }),
        onFailure: (error) => Effect.succeed(error.code),
      }),
    ),
  );
  assert.equal(
    observations.length,
    before + 1,
    "disconnect must deny before egress",
  );
  console.log(
    JSON.stringify({ stage: "connections-after-disconnect", outcome: denied }),
  );
  // The pinned proxy maps connection_not_found to HTTP 400/server_error.
  // That ambiguous envelope also covers refresh failures: it proves refusal,
  // not a terminal credential verdict. See allProxy.js in the pinned image.
  assert.equal(denied, "http_400");
  console.log(JSON.stringify({ stage: "connections-custody-laws-passed" }));
}

// One linear, step-by-step container orchestration script (low cyclomatic/
// cognitive complexity; the line count is sequential setup/teardown, not
// branching); splitting it would only thread the same handful of local
// values (ids, server URL, upstream) through several new parameter lists for
// no readability gain.
async function main() {
  const pulledDigest = docker([
    "inspect",
    IMAGE,
    "--format",
    "{{index .RepoDigests 0}}",
  ]);
  assert.ok(
    pulledDigest.endsWith(PINNED_DIGEST),
    `expected the pinned image digest ${PINNED_DIGEST}, got ${pulledDigest}`,
  );

  const pgPassword = randomBytes(24).toString("hex");
  const encryptionKey = randomBytes(32).toString("base64");

  console.log(
    JSON.stringify({
      stage: "start",
      run,
      image: IMAGE,
      digest: PINNED_DIGEST,
    }),
  );

  startPostgres(pgName, pgPassword);

  try {
    await waitForPostgres(pgName);
    const pgIp = containerIp(pgName);

    const serverUrl = startNango(nangoName, pgIp, pgPassword, encryptionKey);

    try {
      await waitForNangoHealth(serverUrl);
      console.log(JSON.stringify({ stage: "nango-healthy", serverUrl }));

      const devKey = docker([
        "exec",
        pgName,
        "psql",
        "-U",
        "nango",
        "-d",
        "nango",
        "-t",
        "-A",
        "-c",
        "select secret_key from _nango_environments where name = 'dev';",
      ]);
      assert.ok(devKey.length > 0, "dev environment secret key must exist");

      // One-time admin bootstrap: declare the test integration. This is an
      // operator action against this disposable instance, not part of the
      // custodian contract under test.
      const integrationResponse = await fetch(`${serverUrl}/integrations`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${devKey}`,
          "Content-Type": "application/json",
        },
        // "axiom" is an API_KEY provider with no live-provider connection
        // test configured upstream, so a synthetic key can be imported
        // without reaching any real third party.
        body: JSON.stringify({ provider: "axiom", unique_key: integrationKey }),
      });
      assert.equal(integrationResponse.status, 200);

      const custodian = createNangoModelKeyCustodian({
        serverUrl,
        apiKey: devKey,
        integrations: { "openai-compatible": integrationKey },
      });

      // Private test upstream: a loopback-adjacent HTTP server reachable from
      // the Nango container over the host's docker0 bridge. Never a real
      // provider; this is Veil's own private-bridge fixture pattern (see
      // nango-proxy-http.mjs) reused for a full custodian-level proof.
      const bridge = networkInterfaces().docker0?.find(
        (entry) => entry.family === "IPv4" && !entry.internal,
      );
      assert.ok(bridge, "suite D requires an existing docker0 bridge");
      const observations = [];
      const upstream = createServer((request, response) => {
        observations.push({
          method: request.method,
          url: request.url,
          authorization: request.headers.authorization ?? null,
        });
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ ok: true }));
      });
      upstream.listen(0, bridge.address);
      await once(upstream, "listening");
      const upstreamPort = upstream.address().port;
      const baseUrl = `http://${bridge.address}:${upstreamPort}`;

      try {
        // 1. connect: seal a synthetic key through the real server.
        await custodian.seal(
          {
            teamId: `team-${run}`,
            locator: connectionLocator,
            provider: "openai-compatible",
            apiKey: syntheticApiKey,
          },
          new AbortController().signal,
        );
        console.log(JSON.stringify({ stage: "sealed" }));

        // 2. metadata read / final-egress injection: the real server must
        // inject the real credential; Veil never sees or forwards one of its
        // own, and the guest request carries no Authorization at all.
        const access = {
          locator: connectionLocator,
          provider: "openai-compatible",
          baseUrl,
        };
        const guestRequest = new Request(`${baseUrl}/v1/models`, {
          method: "GET",
          headers: new Headers({ accept: "application/json" }),
        });
        const sendResponse = await custodian.send(access, guestRequest);
        assert.equal(sendResponse.status, 200);
        await sendResponse.text();
        assert.equal(observations.length, 1);
        assert.ok(
          observations[0].authorization === `Bearer ${syntheticApiKey}`,
          "the real server must inject the sealed credential at egress",
        );
        console.log(
          JSON.stringify({
            stage: "egress-injected",
            observedAuthorizationMatchesSecret: true,
          }),
        );

        // 2b. backup + key restore into a fresh isolated instance, then a
        // canary scan of the backup by value.
        const backup = await rehearseBackupRestore({
          pgPassword,
          encryptionKey,
          devKey,
          access,
          baseUrl,
          observations,
        });
        assertNoLeak("postgres-backup", backup);
        const requestsBeforeDisconnect = observations.length;

        // 3. disconnect denies later reads before provider egress.
        const removed = await custodian.remove(
          { locator: connectionLocator, provider: "openai-compatible" },
          new AbortController().signal,
        );
        assert.equal(removed, "deleted");
        const afterDisconnect = await custodian.send(
          access,
          new Request(`${baseUrl}/v1/models`, { method: "GET" }),
        );
        assert.notEqual(afterDisconnect.status, 200);
        await afterDisconnect.text();
        assert.equal(
          observations.length,
          requestsBeforeDisconnect,
          "no second upstream request after disconnect: denial happens before egress",
        );
        console.log(JSON.stringify({ stage: "disconnect-denies-read" }));

        await proveConnectionsCustody(serverUrl, devKey, baseUrl, observations);

        // 4. unavailable after a stalled/stopped custodian: the typed
        // adapter must map a real transport failure to VeilError("unavailable"),
        // never hang and never leak a raw cause.
        docker(["stop", "-t", "1", nangoName]);
        await assert.rejects(
          custodian.send(
            access,
            new Request(`${baseUrl}/v1/models`, { method: "GET" }),
          ),
          (error) => error instanceof VeilError && error.code === "unavailable",
        );
        console.log(
          JSON.stringify({
            stage: "unavailable-after-stop",
            code: "unavailable",
          }),
        );
      } finally {
        upstream.closeAllConnections?.();
        await new Promise((resolve) => upstream.close(() => resolve()));
        assertNoLeak(
          "upstream-observations",
          JSON.stringify(
            observations.map((o) => ({ ...o, authorization: undefined })),
          ),
        );
      }
    } finally {
      try {
        const nangoLogs = dockerLogsSince(nangoName, "0");
        assertNoLeak("nango-container-logs", nangoLogs);
      } catch (cause) {
        cleanupFailures.push({ operation: "read Nango container logs", cause });
      } finally {
        removeQuietly(restoreNangoName, "remove restored Nango container");
        removeQuietly(nangoName, "remove Nango container");
      }
    }
  } finally {
    removeQuietly(restorePgName, "remove restore Postgres container");
    removeQuietly(pgName, "remove Postgres container");
  }
}

const outcomes = await Promise.allSettled([main()]);
const failures = [
  ...outcomes.flatMap((outcome) =>
    outcome.status === "rejected" ? [outcome.reason] : [],
  ),
  ...(seenSecretLeaks.length > 0
    ? [
        new Error(
          `synthetic credential value leaked into: ${seenSecretLeaks.join(", ")}`,
        ),
      ]
    : []),
  ...cleanupFailures.map(
    ({ operation, cause }) => new Error(operation, { cause }),
  ),
];
if (failures.length > 0) {
  // Assertion errors can retain credential-bearing actual/expected values.
  // Never print arbitrary causes, Docker argv, response bodies or backups.
  console.error(
    JSON.stringify({
      result: "failed",
      run,
      failureCount: failures.length,
      leakLocations: seenSecretLeaks,
      cleanupOperations: cleanupFailures.map(({ operation }) => operation),
    }),
  );
  process.exitCode = 1;
} else
  console.log(
    JSON.stringify({
      result: "passed",
      run,
      scope:
        "Real isolated local Nango (pinned self-hosted image) + real createNangoModelKeyCustodian: " +
        "connect, final-egress credential injection, backup + original-key restore into a fresh instance " +
        "(secret decrypts and matches; canary absent from backup and logs), disconnect-denies-read, unavailable-after-stop. " +
        "Current Connections adapter: static intake, injection and repeated disconnect against the same native server. " +
        "Not GitHub OAuth refresh/reconnect-required (needs a real GitHub App; excluded per ticket 05), " +
        "not Discord/Etsy/hosted BYOK, not production Nango.",
    }),
  );
