/* global console, setTimeout, fetch, AbortController, Request, Headers */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";
import { networkInterfaces } from "node:os";

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
const nangoName = `veil-suite-d-nango-${run}`;
const integrationKey = `veil-suite-d-${run}`;
const connectionLocator = `suite-d-${run}`;
const syntheticApiKey = `synthetic-suite-d-secret-${run}`;

const seenSecretLeaks = [];
const cleanupFailures = [];
/** Fails loudly, instead of silently passing, if the raw secret ever surfaces
 * anywhere this script can see outside the one expected Nango-side log line
 * it never inspects. */
function assertNoLeak(label, haystack) {
  if (haystack.includes(syntheticApiKey)) seenSecretLeaks.push(label);
}

function docker(args, options = {}) {
  return execFileSync("docker", args, {
    encoding: "utf8",
    ...options,
  }).trim();
}

function dockerLogsSince(name, since) {
  return docker(["logs", "--since", since, name]);
}

async function waitFor(check, { timeoutMs = 30_000, intervalMs = 500 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await check()) return;
    if (Date.now() > deadline) throw new Error("timed out waiting");
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
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

  docker([
    "run",
    "-d",
    "--name",
    pgName,
    "-e",
    "POSTGRES_DB=nango",
    "-e",
    "POSTGRES_USER=nango",
    "-e",
    `POSTGRES_PASSWORD=${pgPassword}`,
    "postgres:16-alpine",
  ]);

  try {
    await waitFor(() => {
      try {
        docker(["exec", pgName, "pg_isready", "-U", "nango"]);
        return true;
      } catch {
        return false;
      }
    });

    const pgIp = docker([
      "inspect",
      "-f",
      "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
      pgName,
    ]);

    docker([
      "run",
      "-d",
      "--name",
      nangoName,
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
      // Isolated test-only egress posture: this disposable instance's proxy
      // is allowed to reach the private test upstream below. The denylist
      // override is emptied for THIS container only; production Nango is
      // never touched or reconfigured by this script.
      "-e",
      "NANGO_PROXY_BASE_URL_OVERRIDE_ENABLED=true",
      "-e",
      "NANGO_PROXY_BASE_URL_OVERRIDE_DENYLIST=[]",
      "-e",
      'NANGO_OUTBOUND_URL_POLICY={"blockPrivateIps":false}',
      IMAGE,
    ]);

    try {
      const hostPort = docker([
        "inspect",
        "-f",
        '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}',
        nangoName,
      ]);
      const serverUrl = `http://127.0.0.1:${hostPort}`;

      await waitFor(async () => {
        try {
          const response = await fetch(`${serverUrl}/health`);
          return response.ok;
        } catch {
          return false;
        }
      });
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
        assert.equal(
          observations[0].authorization,
          `Bearer ${syntheticApiKey}`,
          "the real server must inject the sealed credential at egress",
        );
        console.log(
          JSON.stringify({
            stage: "egress-injected",
            observedAuthorizationMatchesSecret: true,
          }),
        );

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
          1,
          "no second upstream request after disconnect: denial happens before egress",
        );
        console.log(JSON.stringify({ stage: "disconnect-denies-read" }));

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
        try {
          docker(["rm", "-f", nangoName]);
        } catch (cause) {
          cleanupFailures.push({ operation: "remove Nango container", cause });
        }
      }
    }
  } finally {
    try {
      docker(["rm", "-f", pgName]);
    } catch (cause) {
      cleanupFailures.push({ operation: "remove Postgres container", cause });
    }
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
if (failures.length > 0)
  throw new AggregateError(failures, "Veil custody proof or cleanup failed");

console.log(
  JSON.stringify({
    result: "passed",
    run,
    scope:
      "Real isolated local Nango (pinned self-hosted image) + real createNangoModelKeyCustodian: " +
      "connect, final-egress credential injection, disconnect-denies-read, unavailable-after-stop. " +
      "Not GitHub OAuth refresh/reconnect-required (needs a real GitHub App; excluded per ticket 05), " +
      "not Discord/Etsy/hosted BYOK, not production Nango.",
  }),
);
