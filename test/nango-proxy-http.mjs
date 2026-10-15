/* global console, process */
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { networkInterfaces } from "node:os";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

// Transport qualification only. The upstream serves opaque fixture bytes, not
// a Git engine; no Team authorization or Git clone result follows from this.
const source = resolve(process.argv[2]);
assert.equal(
  execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: source,
    encoding: "utf8",
  }).trim(),
  "7c00d83c6d6e6155a2e49a76061d0aa4d6bd464b",
);
const requireNango = createRequire(resolve(source, "package.json"));
const { getProviders } = await import(
  pathToFileURL(requireNango.resolve("@nangohq/providers"))
);
const { resolvePolicyForServer } = await import(
  pathToFileURL(requireNango.resolve("@nangohq/egress"))
);
const shared = dirname(requireNango.resolve("@nangohq/shared"));
const { ProxyRequest } = await import(
  pathToFileURL(resolve(shared, "services/proxy/request.js"))
);
const input = Buffer.from([0, 255, 13, 10, 128, 1, 2, 3]);
const output = Buffer.from([80, 65, 67, 75, 0, 255, 128, 10]);
const secret = "synthetic-proxy-http-credential";
const expectedAuthorization = `Basic ${Buffer.from(`x-access-token:${secret}`).toString("base64")}`;
const observations = [];
const logs = [];
const server = createServer(async (request, response) => {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  observations.push({
    method: request.method,
    path: request.url,
    authorized: request.headers.authorization === expectedAuthorization,
    protocol: request.headers["git-protocol"],
    contentType: request.headers["content-type"],
    bytes: Buffer.concat(chunks),
  });
  response.writeHead(200, {
    "content-type": "application/x-git-upload-pack-result",
  });
  response.write(output.subarray(0, 4));
  response.end(output.subarray(4));
});
// Bind only the existing private Docker bridge, never the public host interface.
// Nango rejects loopback unconditionally; private IPs use its normal test policy.
const bridge = networkInterfaces().docker0?.find(
  (entry) => entry.family === "IPv4" && !entry.internal,
);
assert.ok(
  bridge,
  "Local qualification requires an existing private docker0 interface",
);
assert.equal(bridge.address, "172.17.0.1");
server.listen(0, bridge.address);
await once(server, "listening");
const address = server.address();
assert.ok(address);
assert.equal(address.family, "IPv4");
// Local fixture input only; no production Nango egress policy is changed.
const outboundPolicy = resolvePolicyForServer({
  proxyBaseUrlOverrideDenylist: [],
  outboundUrlPolicy: {
    mode: "allowlist",
    allowlist: [bridge.address],
    blockPrivateIps: false,
    blockLinkLocal: true,
    maxRedirects: 0,
  },
});
let credentialReads = 0;
let available = true;
const makeRequest = () =>
  new ProxyRequest({
    proxyConfig: {
      endpoint: "/owner/repository.git/git-upload-pack?fixture=opaque",
      method: "POST",
      providerConfigKey: "synthetic-git",
      providerName: "synthetic-git",
      provider: {
        ...getProviders()["github-app"],
        proxy: {
          base_url: `http://${bridge.address}:${address.port}`,
          headers: {
            authorization:
              "Basic ${base64(x-access-token:${credentials.access_token})}",
          },
        },
      },
      responseType: "stream",
      decompress: false,
      retries: 0,
      headers: {
        "content-type": "application/x-git-upload-pack-request",
        "git-protocol": "version=2",
      },
      data: input,
    },
    outboundPolicy,
    logger: (event) => {
      logs.push(event);
    },
    getConnection: () => {
      credentialReads += 1;
      if (!available) throw new Error("synthetic connection unavailable");
      return {
        credentials: { type: "APP", access_token: secret },
        connection_config: {},
      };
    },
    getIntegrationConfig: () => {
      throw new Error("APP profile must not request OAuth1 configuration");
    },
  });
try {
  const result = await makeRequest().request();
  if (result.isErr()) {
    console.log(
      JSON.stringify({
        stage: "proxy-request-failed",
        errorClass: result.error?.constructor?.name,
        code: result.error?.code,
        upstreamRequests: observations.length,
      }),
    );
  }
  assert.equal(result.isOk(), true);
  const response = result.unwrap();
  const chunks = [];
  for await (const chunk of response.data) chunks.push(chunk);
  assert.equal(response.status, 200);
  assert.deepEqual(Buffer.concat(chunks), output);
  assert.deepEqual(observations, [
    {
      method: "POST",
      path: "/owner/repository.git/git-upload-pack?fixture=opaque",
      authorized: true,
      protocol: "version=2",
      contentType: "application/x-git-upload-pack-request",
      bytes: input,
    },
  ]);
  available = false;
  assert.equal((await makeRequest().request()).isErr(), true);
  assert.equal(credentialReads, 2);
  assert.equal(observations.length, 1);
  assert.equal(JSON.stringify(logs).includes(secret), false);
  assert.equal(JSON.stringify(logs).includes(expectedAuthorization), false);
  console.log(
    JSON.stringify({
      result: "passed",
      upstreamRequests: observations.length,
      credentialReads,
      requestBytes: input.length,
      responseBytes: output.length,
      scope:
        "Real Nango ProxyRequest with synthetic private-bridge upstream; not Git smart-HTTP, Team authority, service auth or cancellation proof",
    }),
  );
} finally {
  server.closeAllConnections();
  await new Promise((resolveClose, rejectClose) =>
    server.close((error) => (error ? rejectClose(error) : resolveClose())),
  );
}
