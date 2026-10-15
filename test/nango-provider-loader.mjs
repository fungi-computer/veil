/* global console, process */
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

// Run only against the independently hydrated pinned Nango checkout. No aliases,
// copied loader implementation, provider connection or production secret input.
const source = resolve(process.argv[2]);
assert.equal(
  execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: source,
    encoding: "utf8",
  }).trim(),
  "7c00d83c6d6e6155a2e49a76061d0aa4d6bd464b",
);
const requireNango = createRequire(resolve(source, "package.json"));
const providers = await import(
  pathToFileURL(requireNango.resolve("@nangohq/providers"))
);
const original = globalThis.structuredClone(providers.getProviders());
assert.ok(original && Object.keys(original).length > 1);
const githubApp = original["github-app"];
assert.equal(githubApp.auth_mode, "APP");
assert.equal(githubApp.alias, undefined);
assert.equal(githubApp.proxy.base_url, "https://api.github.com");
const profileId = "fungi-github-git-read";
assert.equal(original[profileId], undefined);
const profile = {
  ...githubApp,
  proxy: {
    base_url: "https://github.com",
    headers: {
      authorization:
        "Basic ${base64(x-access-token:${credentials.access_token})}",
    },
  },
};
const serialized = JSON.stringify({ ...original, [profileId]: profile });
let status = 200;
let body = serialized;
let requests = 0;
const server = createServer((request, response) => {
  assert.equal(request.url, "/providers.json");
  requests += 1;
  response.writeHead(status, { "content-type": "application/json" });
  response.end(body);
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
const address = server.address();
assert.ok(address);
assert.equal(address.family, "IPv4");
process.env.PROVIDERS_URL = `http://127.0.0.1:${address.port}/providers.json`;
const shared = dirname(requireNango.resolve("@nangohq/shared"));
try {
  // This is the maintained module reexported by @nangohq/shared to the server.
  const { loadProviders } = await import(
    pathToFileURL(resolve(shared, "services/providers.js"))
  );
  await loadProviders();
  assert.equal(requests, 1);
  const loaded = providers.getProviders();
  assert.equal(Object.keys(loaded).length, Object.keys(original).length + 1);
  for (const [name, provider] of Object.entries(original)) {
    assert.deepEqual(loaded[name], provider, `preserved provider ${name}`);
  }
  assert.deepEqual(providers.getProvider(profileId), profile);

  const { buildProxyHeaders } = await import(
    pathToFileURL(resolve(shared, "services/proxy/utils.js"))
  );
  const connection = {
    credentials: { type: "APP", access_token: "synthetic-local-qualification" },
    connection_config: {},
  };
  const config = {
    provider: profile,
    endpoint: "/owner/repository.git/info/refs",
    method: "GET",
    headers: {},
  };
  const headers = buildProxyHeaders({
    config,
    connection,
    url: "https://github.com/owner/repository.git/info/refs?service=git-upload-pack",
  });
  assert.equal(
    headers.authorization,
    `Basic ${Buffer.from(`x-access-token:${connection.credentials.access_token}`).toString("base64")}`,
  );
  const metadata = buildProxyHeaders({
    config: { ...config, provider: githubApp },
    connection,
    url: "https://api.github.com/repos/owner/repository",
  });
  assert.equal(
    metadata.authorization,
    `Bearer ${connection.credentials.access_token}`,
  );

  status = 503;
  await assert.rejects(loadProviders);
  assert.deepEqual(providers.getProviders(), loaded);
  status = 200;
  body = "{";
  await assert.rejects(loadProviders);
  assert.deepEqual(providers.getProviders(), loaded);
  console.log(
    JSON.stringify({
      result: "passed",
      preservedProviders: Object.keys(original).length,
      addedProfile: profileId,
      providerMapSha256: createHash("sha256").update(serialized).digest("hex"),
      actualHttpLoads: requests,
      syntheticGitHeader: "qualified",
      metadataHeader: "unchanged",
      failedReloadPreservesMap: true,
      scope:
        "Maintained package/HTTP loader/header builder only; no GitHub or Git smart-HTTP request",
    }),
  );
} finally {
  server.closeAllConnections();
  await new Promise((resolveClose, rejectClose) =>
    server.close((error) => (error ? rejectClose(error) : resolveClose())),
  );
}
