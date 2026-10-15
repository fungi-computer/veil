/* global process */
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

assert.ok(process.env.NANGO_QUALIFICATION_SOURCE);
const source = resolve(process.env.NANGO_QUALIFICATION_SOURCE);
const requireNango = createRequire(join(source, "package.json"));
const { defineConfig } = await import(
  pathToFileURL(requireNango.resolve("vitest/config"))
);
const root = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    root,
    include: ["nango-git-route.integration.test.mjs"],
    globalSetup: [join(root, "nango-git-route.setup.mjs")],
    fileParallelism: false,
    maxWorkers: 1,
    pool: "forks",
    hookTimeout: 120000,
    testTimeout: 60000,
    env: {
      NODE_ENV: "test",
      NANGO_QUALIFICATION_SOURCE: source,
      // Public synthetic key for this disposable fixture, never operational custody.
      NANGO_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64"),
      NANGO_LOGS_ENABLED: "true",
      NANGO_LOGS_ES_PREFIX: "test",
      NANGO_PUBSUB_TRANSPORT: "none",
      FLAG_PLAN_ENABLED: "true",
      FLAG_API_RATE_LIMIT_ENABLED: "false",
      FLAG_AUTH_ROLES_ENABLED: "true",
      ORCHESTRATOR_SERVICE_URL: "http://orchestrator",
      RUNNER_NODE_ID: "1",
      DD_TRACE_ENABLED: "false",
      DD_INSTRUMENTATION_TELEMETRY_ENABLED: "false",
      NANGO_OUTBOUND_URL_POLICY: JSON.stringify({
        mode: "allowlist",
        allowlist: ["172.17.0.1"],
        blockPrivateIps: false,
        blockLinkLocal: true,
        maxRedirects: 0,
      }),
    },
  },
});
