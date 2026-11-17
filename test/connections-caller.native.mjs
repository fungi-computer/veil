/* global fetch, console, process */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:https";
import { createServer as createPortReservation } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout } from "node:timers/promises";
import { createNangoCustody } from "../src/connections/nango.js";
import {
  proveConnectionsCaller,
  repository,
} from "./fixtures/connections-caller-laws.js";

// Same pinned server as suite D; no production services, credentials or provider.
// Run with tsx. Fixture TLS is trusted only inside this disposable Nango container.
const image =
  "nangohq/nango-server@sha256:cc2419c46221e6b4f6fa72f08a11bf69632cc7ebacc0658a44eb745927d9046a";
const run = randomUUID().slice(0, 8);
const pg = `veil-caller-pg-${run}`;
const nango = `veil-caller-nango-${run}`;
const integration = `caller-${run}`;
const secret = randomBytes(32).toString("hex");
const password = randomBytes(24).toString("hex");
const key = randomBytes(32).toString("base64");
const cleanup = [];
let stage = "setup";
const command = (name, args) => {
  try {
    return execFileSync(name, args, {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
  } catch {
    throw new Error("fixture command failed");
  }
};
const docker = (args) => command("docker", args);
async function waitFor(check) {
  let outcome;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    [outcome] = await Promise.allSettled([Promise.resolve().then(check)]);
    if (outcome.status === "fulfilled" && outcome.value) return;
    await setTimeout(500);
  }
  throw new Error("fixture readiness timed out", { cause: outcome });
}
async function main() {
  const directory = await mkdtemp(join(tmpdir(), "veil-caller-tls-"));
  cleanup.push(() => rm(directory, { recursive: true, force: true }));
  const bridge = networkInterfaces().docker0?.find(
    (entry) => entry.family === "IPv4" && !entry.internal,
  );
  assert.ok(bridge, "existing Docker bridge required");
  command("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    join(directory, "key.pem"),
    "-out",
    join(directory, "cert.pem"),
    "-days",
    "1",
    "-subj",
    "/CN=metadata.example.com",
    "-addext",
    "subjectAltName=DNS:metadata.example.com",
  ]);
  let count = 0;
  let status = 200;
  let injectionValid = true;
  const upstream = createServer(
    {
      key: await readFile(join(directory, "key.pem")),
      cert: await readFile(join(directory, "cert.pem")),
    },
    (request, response) => {
      count += 1;
      injectionValid &&=
        request.headers.authorization === `Bearer ${secret}` &&
        request.url === "/repos/fixture/selected";
      response.writeHead(status, { "content-type": "application/json" });
      response.end(JSON.stringify(repository));
    },
  );
  upstream.listen(0, bridge.address);
  await once(upstream, "listening");
  cleanup.push(async () => {
    upstream.closeAllConnections();
    await new Promise((resolve) => upstream.close(resolve));
  });
  const baseUrl = `https://metadata.example.com:${upstream.address().port}`;
  cleanup.push(() => {
    docker(["rm", "-f", pg]);
  });
  docker([
    "run",
    "-d",
    "--name",
    pg,
    "-e",
    "POSTGRES_DB=nango",
    "-e",
    "POSTGRES_USER=nango",
    "-e",
    `POSTGRES_PASSWORD=${password}`,
    "postgres:16-alpine",
  ]);
  await waitFor(() =>
    docker(["exec", pg, "pg_isready", "-U", "nango"]).includes(
      "accepting connections",
    ),
  );
  const pgIp = docker([
    "inspect",
    "-f",
    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
    pg,
  ]);
  // Docker's host-port 0 changes on restart. Reserve a port, then publish it
  // explicitly so the existing adapter keeps the same origin through recovery.
  const reservation = createPortReservation();
  reservation.listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const serverPort = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  cleanup.push(() => {
    docker(["rm", "-f", nango]);
  });
  docker([
    "run",
    "-d",
    "--name",
    nango,
    "-p",
    `127.0.0.1:${serverPort}:8080`,
    "--add-host",
    `metadata.example.com:${bridge.address}`,
    "--mount",
    `type=bind,src=${join(directory, "cert.pem")},dst=/fixture-ca.pem,readonly`,
    "-e",
    "NODE_EXTRA_CA_CERTS=/fixture-ca.pem",
    "-e",
    `NANGO_DB_HOST=${pgIp}`,
    "-e",
    "NANGO_DB_PORT=5432",
    "-e",
    "NANGO_DB_USER=nango",
    "-e",
    `NANGO_DB_PASSWORD=${password}`,
    "-e",
    "NANGO_DB_NAME=nango",
    "-e",
    `NANGO_ENCRYPTION_KEY=${key}`,
    "-e",
    "SERVER_PORT=8080",
    "-e",
    "NANGO_SERVER_PORT=8080",
    "-e",
    "NANGO_LOGS_ENABLED=false",
    "-e",
    "NANGO_TELEMETRY=false",
    "-e",
    "NANGO_PROXY_BASE_URL_OVERRIDE_ENABLED=true",
    "-e",
    "NANGO_PROXY_BASE_URL_OVERRIDE_DENYLIST=[]",
    "-e",
    'NANGO_OUTBOUND_URL_POLICY={"blockPrivateIps":false}',
    image,
  ]);
  const port = docker([
    "inspect",
    "-f",
    '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}',
    nango,
  ]);
  const serverUrl = `http://127.0.0.1:${port}`;
  await waitFor(async () => (await fetch(`${serverUrl}/health`)).ok);
  const apiKey = docker([
    "exec",
    pg,
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
  const configured = await fetch(`${serverUrl}/integrations`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ provider: "axiom", unique_key: integration }),
  });
  assert.equal(configured.status, 200);
  let paused = false;
  const resume = async () => {
    if (paused) {
      docker(["start", nango]);
      await waitFor(async () => (await fetch(`${serverUrl}/health`)).ok);
      paused = false;
    }
    return Promise.resolve();
  };
  cleanup.push(resume);
  stage = "caller-laws";
  await proveConnectionsCaller({
    custody: createNangoCustody({
      serverUrl,
      apiKey,
      webhookSigningKey: "unused-static-ceremony",
      staticIntegrationId: integration,
      connectBaseUrl: "https://connect.example.com/",
      publicApiUrl: "https://connect.example.com",
      requestTimeoutMs: 1000,
    }),
    baseUrl,
    secret,
    requests: () => count,
    pause: () => {
      docker(["stop", "-t", "1", nango]);
      paused = true;
      return Promise.resolve();
    },
    resume,
    providerStatus: (next) => {
      status = next;
    },
  });
  assert.equal(
    injectionValid,
    true,
    "native proxy injects only at the selected repository",
  );
  stage = "canary-scan";
  const logs = spawnSync("docker", ["logs", nango], { encoding: "utf8" });
  assert.equal(logs.status, 0);
  for (const output of [logs.stdout, logs.stderr])
    for (const canary of [secret, apiKey, key, password])
      assert.equal(
        output.includes(canary),
        false,
        "no credential canary in either log stream",
      );
}
const [outcome] = await Promise.allSettled([main()]);
const failures =
  outcome.status === "rejected" ? [{ stage, cause: outcome.reason }] : [];
for (const close of cleanup.reverse()) {
  const [closed] = await Promise.allSettled([Promise.resolve().then(close)]);
  if (closed.status === "rejected")
    failures.push({ stage: "cleanup", cause: closed.reason });
}
if (failures.length > 0) {
  // Retain each failure, but print only its local assertion location. Never
  // serialize the raw cause: child errors can contain credential-bearing argv.
  for (const failure of failures) {
    const line =
      failure.cause instanceof Error
        ? /connections-caller-laws\.ts:(\d+):/u.exec(
            failure.cause.stack ?? "",
          )?.[1]
        : undefined;
    console.error(
      JSON.stringify({
        result: "failed",
        stage: failure.stage,
        callerLine: line,
      }),
    );
  }
  process.exitCode = 1;
} else {
  console.log(
    JSON.stringify({
      result: "passed",
      run,
      image,
      scope:
        "shared Connections caller, synthetic static custody; no live OAuth ceremony",
    }),
  );
}
