/* global fetch, process */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL, URL } from "node:url";
import { promisify } from "node:util";

import { startGitFixture } from "./nango-git-fixture.mjs";

// Executed only in the pinned Nango Vitest process with isolated database/log
// services. All credentials are locally seeded synthetic fixture values.
assert.ok(process.env.NANGO_QUALIFICATION_SOURCE);
const source = resolve(process.env.NANGO_QUALIFICATION_SOURCE);
const requireNango = createRequire(join(source, "package.json"));
const load = (name) => import(pathToFileURL(requireNango.resolve(name)));
// Pinned Vitest 4.1.9 exports dist/index.js for ESM. Its require condition
// intentionally points to an index.cjs that throws, even under dynamic import.
const { test, expect, afterAll } = await import(
  pathToFileURL(
    join(dirname(requireNango.resolve("vitest/package.json")), "dist/index.js"),
  )
);
const { default: getPort } = await load("get-port");
const { getProviders, updateProviderCache } = await load("@nangohq/providers");
const { seeders } = await load("@nangohq/shared");
const { runServer } = await import(
  pathToFileURL(join(source, "packages/server/dist/utils/tests.js"))
);
const { default: database } = await load("@nangohq/database");
const { destroy: destroyLogs } = await load("@nangohq/logs");
const { records } = await load("@nangohq/records");
const { tasks } = await import(
  pathToFileURL(join(source, "packages/server/dist/tasks/index.js"))
);
const { egressTelemetryRecorder } = await import(
  pathToFileURL(join(source, "packages/server/dist/utils/egressTelemetry.js"))
);
const exec = promisify(execFile);

afterAll(async () => {
  // Same maintained cleanup owners as server.ts for the resources this fixture
  // imports/migrates. Vitest worker termination is not resource settlement.
  const outcomes = await Promise.allSettled([
    tasks.stop(),
    database.destroy(),
    records.close(),
    destroyLogs(),
    egressTelemetryRecorder.shutdown(),
  ]);
  const errors = outcomes.flatMap((outcome) => {
    if (outcome.status === "rejected") return [outcome.reason];
    return outcome.value?.isErr() ? [outcome.value.error] : [];
  });
  if (errors.length)
    throw new AggregateError(errors, "Nango fixture cleanup failed");
});

test("native Git clones through the authenticated Nango proxy route", async () => {
  const { stdout: sourceRevision } = await exec("git", ["rev-parse", "HEAD"], {
    cwd: source,
  });
  assert.equal(
    sourceRevision.trim(),
    "7c00d83c6d6e6155a2e49a76061d0aa4d6bd464b",
  );
  const fixture = await startGitFixture({ port: await getPort() });
  const cloneRoot = await mkdtemp(join(tmpdir(), "veil-nango-clone-"));
  let api;
  try {
    await expect.poll(async () => (await fetch(fixture.url)).status).toBe(401);
    const providers = getProviders();
    const profile = "fungi-github-git-read";
    // The real loader's complete-map behavior is independently qualified. Here
    // the maintained cache setter seeds that same resolved profile shape, with
    // only its upstream changed to the local native Git CGI fixture.
    updateProviderCache({
      ...providers,
      [profile]: {
        ...providers["github-app"],
        proxy: {
          base_url: new URL("/", fixture.url).origin,
          headers: {
            authorization:
              "Basic ${base64(x-access-token:${credentials.access_token})}",
          },
        },
      },
    });
    api = await runServer();
    const { env, apiKey } = await seeders.seedAccountEnvAndUser();
    const integration = await seeders.createConfigSeed(env, profile, profile);
    const connection = await seeders.createConnectionSeed({
      env,
      provider: integration.unique_key,
      config_id: integration.id,
      rawCredentials: { type: "APP", access_token: fixture.credential },
    });
    const url = `${api.url}/proxy${new URL(fixture.url).pathname}`;
    assert.equal(
      (await fetch(`${url}/info/refs?service=git-upload-pack`)).status,
      401,
    );
    const stranger = await seeders.seedAccountEnvAndUser();
    await seeders.createConfigSeed(stranger.env, profile, profile);
    const isolated = await fetch(`${url}/info/refs?service=git-upload-pack`, {
      headers: {
        Authorization: `Bearer ${stranger.apiKey.secret}`,
        "Provider-Config-Key": integration.unique_key,
        "Connection-Id": connection.connection_id,
      },
    });
    // Pinned proxyService's connection_not_found status is 400. The same
    // integration name in another environment must not resolve this connection.
    assert.equal(isolated.status, 400);
    // Synthetic API credentials stay in this test process, never repository
    // files. This is not the production Computer caller or its credential path.
    const headers = [
      `Authorization: Bearer ${apiKey.secret}`,
      `Provider-Config-Key: ${integration.unique_key}`,
      `Connection-Id: ${connection.connection_id}`,
      "Nango-Proxy-Content-Type: application/x-git-upload-pack-request",
      "Nango-Proxy-Git-Protocol: version=2",
    ];
    const gitEnv = { PATH: "/usr/bin:/bin", GIT_TERMINAL_PROMPT: "0" };
    gitEnv.GIT_CONFIG_COUNT = String(headers.length);
    for (const [i, header] of headers.entries()) {
      gitEnv[`GIT_CONFIG_KEY_${String(i)}`] = `http.${api.url}/.extraHeader`;
      gitEnv[`GIT_CONFIG_VALUE_${String(i)}`] = header;
    }
    const checkout = join(cloneRoot, "checkout");
    await exec("git", ["clone", url, checkout], {
      env: gitEnv,
      timeout: 30000,
    });
    const { stdout: revision } = await exec("git", ["rev-parse", "HEAD"], {
      cwd: checkout,
    });
    assert.equal(revision.trim(), fixture.revision);
    assert.equal(
      await readFile(join(checkout, "README.md"), "utf8"),
      "Synthetic Nango Git fixture.\n",
    );
    assert.deepEqual(
      new Uint8Array(await readFile(join(checkout, "bytes.bin"))),
      new Uint8Array([0, 255, 128, 10]),
    );
    const gitConfig = await readFile(join(checkout, ".git", "config"), "utf8");
    assert.equal(gitConfig.includes(apiKey.secret), false);
    assert.equal(gitConfig.includes(fixture.credential), false);
  } finally {
    try {
      if (api) {
        api.server.closeAllConnections();
        await new Promise((done, reject) =>
          api.server.close((error) => (error ? reject(error) : done())),
        );
      }
    } finally {
      try {
        await fixture.close();
      } finally {
        await rm(cloneRoot, { recursive: true, force: true });
      }
    }
  }
}, 60000);
