import * as Schema from "effect/Schema";
import { afterEach, expect, it, vi } from "vitest";
import {
  createOpenApiDoor,
  OpenApiError,
  type OpenApiAccess,
  type OpenApiCredentialAddress,
  type OpenApiCredentialStore,
} from "../src/openapi.js";
import type { PublicConnect, PublicSocket } from "../src/public-fetch.js";

const publicIp = "93.184.215.14";
const encode = new TextEncoder();
const decode = new TextDecoder();
const access: OpenApiAccess = {
  teamId: "team-a",
  connectorId: "connector-a",
  baseUrl: "https://pets.example/v1",
  auth: { kind: "none" },
};

/** Only the host socket is substituted: Veil still parses and frames real HTTP bytes. */
function network(
  reply = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{"ok":true}',
) {
  const requests: string[] = [];
  const addresses: string[] = [];
  const tlsNames: string[] = [];
  let closed = 0;
  const connect: PublicConnect = ({ hostname }) => {
    addresses.push(hostname);
    let release: () => void = () => undefined;
    const written = new Promise<void>((resolve) => {
      release = resolve;
    });
    let sent = false;
    const socket: PublicSocket = {
      opened: Promise.resolve(),
      readable: new ReadableStream<Uint8Array>({
        async pull(controller) {
          await written;
          if (sent) controller.close();
          else {
            sent = true;
            controller.enqueue(encode.encode(reply));
          }
        },
      }),
      writable: new WritableStream<Uint8Array>({
        write(bytes) {
          requests.push(decode.decode(bytes));
          release();
        },
      }),
      startTls({ expectedServerHostname }) {
        tlsNames.push(expectedServerHostname);
        return socket;
      },
      close() {
        closed += 1;
        return Promise.resolve();
      },
    };
    return socket;
  };
  return { connect, requests, addresses, tlsNames, closed: () => closed };
}

it("sends an anonymous OpenAPI write through the checked socket and keeps the pinned origin", async () => {
  const net = network();
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve: () => Promise.resolve([publicIp]),
  });
  const response = await door.send(
    access,
    new Request("https://pets.example/v1/pets?q=1", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"name":"Rex"}',
    }),
  );
  expect(await response.json()).toEqual({ ok: true });
  expect(net.addresses).toEqual([publicIp]);
  expect(net.tlsNames).toEqual(["pets.example"]);
  expect(net.requests.join("")).toContain("POST /v1/pets?q=1 HTTP/1.1\r\n");
  expect(net.requests.join("")).toContain("Content-Length: 14\r\n");
  expect(net.requests.join("")).toContain('{"name":"Rex"}');
});

const masterKey = Buffer.alloc(32, 11).toString("base64url");
const syntheticCredential = "synthetic-openapi-canary";
const signal = () => new AbortController().signal;
function storage() {
  const rows = new Map<string, string>();
  const key = ({ teamId, connectorId }: OpenApiCredentialAddress) =>
    JSON.stringify([teamId, connectorId]);
  const store: OpenApiCredentialStore = {
    read: (address) => Promise.resolve(rows.get(key(address)) ?? null),
    write: (address, sealed) => {
      rows.set(key(address), sealed);
      return Promise.resolve();
    },
    remove: (address) =>
      Promise.resolve(rows.delete(key(address)) ? "deleted" : "absent"),
  };
  return { rows, store };
}
function credentialed(auth: OpenApiAccess["auth"]) {
  const net = network();
  const { rows, store } = storage();
  const options = {
    connect: net.connect,
    resolve: () => Promise.resolve([publicIp]),
    custody: {
      keys: { activeKeyId: "test", keys: { test: masterKey } },
      store,
    },
  };
  return {
    net,
    rows,
    store,
    options,
    access: { ...access, auth },
    door: createOpenApiDoor(options),
  };
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

it.each([
  [
    { kind: "bearer" } as const,
    "authorization: Bearer synthetic-openapi-canary\r\n",
  ],
  [
    { kind: "api_key_header", param: "X-API-Key" } as const,
    "x-api-key: synthetic-openapi-canary\r\n",
  ],
  [
    { kind: "api_key_query", param: "key" } as const,
    "GET /v1/pets?key=synthetic-openapi-canary HTTP/1.1\r\n",
  ],
])(
  "injects $0.kind only at pinned egress; reopening reads ciphertext, remove refuses later calls",
  async (auth, wire) => {
    const c = credentialed(auth);
    await c.door.seal(c.access, syntheticCredential, signal());
    expect(JSON.stringify([...c.rows])).not.toContain(syntheticCredential);
    const reopened = createOpenApiDoor(c.options);
    const result = await reopened.send(
      c.access,
      new Request("https://pets.example/v1/pets"),
    );
    expect(await result.json()).toEqual({ ok: true });
    expect(result.headers.get("set-cookie")).toBeNull();
    expect(c.net.requests.join("")).toContain(wire);
    expect(c.net.addresses).toEqual([publicIp]);
    expect(await reopened.remove(c.access, signal())).toBe("deleted");
    expect(await reopened.remove(c.access, signal())).toBe("absent");
    await expect(
      reopened.send(c.access, new Request("https://pets.example/v1/pets")),
    ).rejects.toMatchObject({ code: "credentials_missing" });
  },
);

it.each([
  "upgrade",
  "te",
  "trailer",
  "keep-alive",
  "expect",
  "via",
  "forwarded",
  "x-real-ip",
  "max-forwards",
  "X-HTTP-Method-Override",
  "X-Method-Override",
  "X-HTTP-Method",
  "authorization",
  "cookie",
  "host",
  "proxy-authorization",
  "x-forwarded-host",
  "content-length",
  "transfer-encoding",
  "connection",
  "nango-proxy-authorization",
  "X-API-Key",
])("refuses the caller's %s header before a socket opens", async (name) => {
  const c = credentialed({ kind: "api_key_header", param: "X-API-Key" });
  await c.door.seal(c.access, syntheticCredential, signal());
  await expect(
    c.door.send(
      c.access,
      new Request("https://pets.example/v1/pets", {
        headers: { [name]: "attacker" },
      }),
      [name],
    ),
  ).rejects.toMatchObject({ code: "denied" });
  expect(c.net.requests).toEqual([]);
});

it("refuses an auth query parameter supplied by the caller", async () => {
  const c = credentialed({ kind: "api_key_query", param: "key" });
  await c.door.seal(c.access, syntheticCredential, signal());
  await expect(
    c.door.send(
      c.access,
      new Request("https://pets.example/v1/pets?key=attacker"),
    ),
  ).rejects.toMatchObject({ code: "denied" });
  expect(c.net.addresses).toEqual([]);
});

it.each([
  "https://elsewhere.example/v1/pets",
  "https://pets.example/v10/pets",
  "https://pets.example/admin",
  "https://pets.example/v1/%2fadmin",
  "https://pets.example/v1/%252e%252e/admin",
])("refuses a target outside its pinned origin/base path: %s", async (url) => {
  const net = network();
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve: () => Promise.resolve([publicIp]),
  });
  await expect(door.send(access, new Request(url))).rejects.toMatchObject({
    code: "denied",
  });
  expect(net.addresses).toEqual([]);
});

it.each([
  "127.0.0.1",
  "10.1.2.3",
  "169.254.169.254",
  "::1",
  "::ffff:127.0.0.1",
  "fd00::1",
])("refuses DNS answer %s without opening a socket", async (address) => {
  const net = network();
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve: () => Promise.resolve([address]),
  });
  await expect(
    door.send(access, new Request("https://pets.example/v1/pets")),
  ).rejects.toMatchObject({ code: "denied" });
  expect(net.addresses).toEqual([]);
});

it("pins a public answer and rejects the next call's rebound private answer", async () => {
  const net = network();
  let lookups = 0;
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve: () =>
      Promise.resolve(++lookups === 1 ? [publicIp] : ["127.0.0.1"]),
  });
  await door.send(access, new Request("https://pets.example/v1/pets"));
  await expect(
    door.send(access, new Request("https://pets.example/v1/pets")),
  ).rejects.toMatchObject({ code: "denied" });
  expect(lookups).toBe(2);
  expect(net.addresses).toEqual([publicIp]);
});

it.each(["http://127.0.0.1/admin", "https://other.example/steal"])(
  "never follows an upstream redirect to %s",
  async (location) => {
    const net = network(
      `HTTP/1.1 302 Found\r\nLocation: ${location}\r\nContent-Length: 0\r\n\r\n`,
    );
    const door = createOpenApiDoor({
      connect: net.connect,
      resolve: () => Promise.resolve([publicIp]),
    });
    await expect(
      door.send(access, new Request("https://pets.example/v1/pets")),
    ).rejects.toMatchObject({ code: "upstream_status", status: 302 });
    expect(net.addresses).toEqual([publicIp]);
    expect(net.closed()).toBeGreaterThan(0);
  },
);

it("authenticates the Team, Connector, base URL and auth policy against copied ciphertext", async () => {
  const c = credentialed({ kind: "bearer" });
  await c.door.seal(c.access, syntheticCredential, signal());
  const sealed = [...c.rows.values()][0];
  expect(sealed).toBeDefined();
  if (sealed === undefined) throw new Error("seal produced no ciphertext");
  for (const changed of [
    { teamId: "team-b" },
    { connectorId: "connector-b" },
    { baseUrl: "https://elsewhere.example/v1" },
    { auth: { kind: "api_key_header", param: "X-Key" } as const },
  ]) {
    const other = { ...c.access, ...changed };
    await c.store.write(other, sealed, signal());
    await expect(
      c.door.send(other, new Request(`${other.baseUrl}/pets`)),
    ).rejects.toMatchObject({ code: "denied" });
  }
  expect(c.net.addresses).toEqual([]);
});

it("rejects corrupt ciphertext and secrets that cannot be sent as a header", async () => {
  const c = credentialed({ kind: "bearer" });
  await expect(
    c.door.seal(c.access, "canary\r\nHost: inward", signal()),
  ).rejects.toMatchObject({ code: "invalid_input" });
  expect(c.rows.size).toBe(0);
  await c.store.write(c.access, '{"iv":"bad","ciphertext":"bad"}', signal());
  await expect(
    c.door.send(c.access, new Request("https://pets.example/v1/pets")),
  ).rejects.toMatchObject({ code: "denied" });
});

it("does not expose an upstream's echoed credential or sensitive headers", async () => {
  const c = credentialed({ kind: "bearer" });
  const net = network(
    `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: ${syntheticCredential}\r\nContent-Length: ${String(syntheticCredential.length)}\r\n\r\n${syntheticCredential}`,
  );
  const door = createOpenApiDoor({ ...c.options, connect: net.connect });
  await door.seal(c.access, syntheticCredential, signal());
  const redacted = await door.send(
    c.access,
    new Request("https://pets.example/v1/pets"),
  );
  expect(await redacted.text()).toBe("[REDACTED]");
  const headers = network(
    `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: ${syntheticCredential}\r\nX-Auth: ${syntheticCredential}\r\nContent-Length: 2\r\n\r\nok`,
  );
  const response = await createOpenApiDoor({
    ...c.options,
    connect: headers.connect,
  }).send(c.access, new Request("https://pets.example/v1/pets"));
  expect([...response.headers]).toEqual([["content-type", "text/plain"]]);
});

it("refuses a 257 KiB request before egress and a 257 KiB streamed response", async () => {
  const body = "x".repeat(257 * 1024);
  const net = network();
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve: () => Promise.resolve([publicIp]),
  });
  await expect(
    door.send(
      access,
      new Request("https://pets.example/v1/pets", { method: "POST", body }),
    ),
  ).rejects.toMatchObject({ code: "too_large" });
  expect(net.addresses).toEqual([]);
  const upstream = network(
    `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n${body}`,
  );
  await expect(
    createOpenApiDoor({
      connect: upstream.connect,
      resolve: () => Promise.resolve([publicIp]),
    }).send(access, new Request("https://pets.example/v1/pets")),
  ).rejects.toMatchObject({ code: "too_large" });
  expect(upstream.closed()).toBeGreaterThan(0);
});

it("accepts the exact 256 KiB limit and refuses non-text/non-JSON response media", async () => {
  const body = "x".repeat(256 * 1024);
  const net = network(
    `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${String(body.length)}\r\n\r\n${body}`,
  );
  const response = await createOpenApiDoor({
    connect: net.connect,
    resolve: () => Promise.resolve([publicIp]),
  }).send(
    access,
    new Request("https://pets.example/v1/pets", { method: "POST", body }),
  );
  expect((await response.text()).length).toBe(256 * 1024);
  const binary = network(
    "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 2\r\n\r\nxx",
  );
  await expect(
    createOpenApiDoor({
      connect: binary.connect,
      resolve: () => Promise.resolve([publicIp]),
    }).send(access, new Request("https://pets.example/v1/pets")),
  ).rejects.toMatchObject({ code: "invalid_response" });
});

it("refuses unconfigured custody and OAuth without falling through to anonymous egress", async () => {
  const net = network();
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve: () => Promise.resolve([publicIp]),
  });
  await expect(
    door.send(
      { ...access, auth: { kind: "bearer" } },
      new Request("https://pets.example/v1/pets"),
    ),
  ).rejects.toMatchObject({ code: "unavailable" });
  await expect(
    door.send(
      {
        ...access,
        auth: { kind: "oauth", provider: "github", locator: "private-locator" },
      },
      new Request("https://pets.example/v1/pets"),
    ),
  ).rejects.toMatchObject({ code: "oauth_not_configured" });
  expect(net.addresses).toEqual([]);
});

it("cancels a socket that never opens and bounds the whole call at 30 seconds", async () => {
  const net = network();
  const connect: PublicConnect = (address, options) => ({
    ...net.connect(address, options),
    opened: new Promise(() => undefined),
  });
  const door = createOpenApiDoor({
    connect,
    resolve: () => Promise.resolve([publicIp]),
  });
  const abort = new AbortController();
  const pending = door.send(
    access,
    new Request("https://pets.example/v1/pets", { signal: abort.signal }),
  );
  await new Promise((resolve) => setTimeout(resolve, 5));
  abort.abort();
  await expect(pending).rejects.toMatchObject({ code: "cancelled" });
  expect(net.closed()).toBeGreaterThan(0);
  vi.useFakeTimers();
  const timeout = door.send(
    access,
    new Request("https://pets.example/v1/pets"),
  );
  const checked = expect(timeout).rejects.toMatchObject({ code: "timeout" });
  await vi.advanceTimersByTimeAsync(30_001);
  await checked;
});

it("sends only declared custom headers and rejects unknown ones", async () => {
  const net = network();
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve: () => Promise.resolve([publicIp]),
  });
  const request = () =>
    new Request("https://pets.example/v1/pets", {
      headers: { "X-Cursor": "next" },
    });
  await expect(door.send(access, request())).rejects.toMatchObject({
    code: "denied",
  });
  await door.send(access, request(), ["X-Cursor"]);
  expect(net.requests.join("")).toContain("x-cursor: next\r\n");
});

it("confines OAuth to a host-configured provider base and its existing private proxy port", async () => {
  const net = network();
  const requests: Request[] = [];
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve: () => Promise.resolve([publicIp]),
    oauthProviders: {
      github: {
        baseUrl: "https://api.github.com",
        send: (teamId, locator, request) => {
          expect(teamId).toBe(access.teamId);
          expect(locator).toBe("private-locator");
          requests.push(request);
          return Promise.resolve(Response.json({ ok: true }));
        },
      },
    },
  });
  const oauth = {
    ...access,
    baseUrl: "https://api.github.com",
    auth: {
      kind: "oauth",
      provider: "github",
      locator: "private-locator",
    } as const,
  };
  await expect(
    door.send(
      { ...oauth, baseUrl: "https://elsewhere.example" },
      new Request("https://elsewhere.example/repository"),
    ),
  ).rejects.toMatchObject({ code: "denied" });
  expect(
    await (
      await door.send(oauth, new Request("https://api.github.com/repository"))
    ).json(),
  ).toEqual({ ok: true });
  expect(requests).toHaveLength(1);
  expect(requests[0]?.redirect).toBe("manual");
  expect(net.addresses).toEqual([]);
});

it("credentialed DNS checks refuse private answers before sending any credential", async () => {
  const c = credentialed({ kind: "bearer" });
  const door = createOpenApiDoor({
    ...c.options,
    resolve: () => Promise.resolve([publicIp, "10.0.0.1"]),
  });
  await door.seal(c.access, syntheticCredential, signal());
  await expect(
    door.send(c.access, new Request("https://pets.example/v1/pets")),
  ).rejects.toMatchObject({ code: "denied" });
  expect(c.net.addresses).toEqual([]);
  expect(c.net.requests).toEqual([]);
});

it("does not log or expose credential bytes from socket failures", async () => {
  const logs = [
    vi.spyOn(console, "log"),
    vi.spyOn(console, "warn"),
    vi.spyOn(console, "error"),
  ];
  const c = credentialed({ kind: "bearer" });
  const door = createOpenApiDoor({
    ...c.options,
    connect: () => {
      throw new Error(syntheticCredential);
    },
  });
  await door.seal(c.access, syntheticCredential, signal());
  await expect(
    door.send(c.access, new Request("https://pets.example/v1/pets")),
  ).rejects.toSatisfy((error: OpenApiError) => {
    expect(error).toBeInstanceOf(OpenApiError);
    expect(error).toMatchObject({ code: "unavailable" });
    expect(JSON.stringify(error)).not.toContain(syntheticCredential);
    expect(String(error)).not.toContain(syntheticCredential);
    return true;
  });
  for (const log of logs) expect(log).not.toHaveBeenCalled();
});

it("preserves a HEAD response without waiting for the advertised GET body", async () => {
  const net = network(
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n",
  );
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve: () => Promise.resolve([publicIp]),
  });
  const response = await door.send(
    access,
    new Request("https://pets.example/v1/pets", { method: "HEAD" }),
  );
  expect(response.status).toBe(200);
  expect(await response.text()).toBe("");
  expect(net.closed()).toBeGreaterThan(0);
});

it("refuses non-443 ports before opening a socket unless the host explicitly permits them", async () => {
  const net = network();
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve: () => Promise.resolve([publicIp]),
  });
  const pinned = { ...access, baseUrl: "https://pets.example:22/v1" };
  await expect(
    door.send(pinned, new Request("https://pets.example:22/v1/pets")),
  ).rejects.toMatchObject({ code: "denied" });
  expect(net.addresses).toEqual([]);
});

it("permits only the host's explicitly configured extra port", async () => {
  const net = network();
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve: () => Promise.resolve([publicIp]),
    networkPolicy: { extraPorts: [8443] },
  });
  const pinned = { ...access, baseUrl: "https://pets.example:8443/v1" };
  expect(
    (await door.send(pinned, new Request("https://pets.example:8443/v1/pets")))
      .status,
  ).toBe(200);
  await expect(
    door.send(
      { ...pinned, baseUrl: "https://pets.example:22/v1" },
      new Request("https://pets.example:22/v1/pets"),
    ),
  ).rejects.toMatchObject({ code: "denied" });
  expect(net.addresses).toHaveLength(1);
});

it.each([
  { kind: "none" } as const,
  { kind: "bearer" } as const,
  { kind: "api_key_header", param: "X-Key" } as const,
  { kind: "api_key_query", param: "key" } as const,
  { kind: "oauth", provider: "github", locator: "private" } as const,
])("refuses plaintext bases before sealing or egress ($kind)", async (auth) => {
  const c = credentialed(auth);
  const plaintext = { ...c.access, baseUrl: "http://pets.example:443/v1" };
  await expect(
    c.door.seal(plaintext, syntheticCredential, signal()),
  ).rejects.toMatchObject({ code: "invalid_input" });
  await expect(
    c.door.send(plaintext, new Request("http://pets.example:443/v1/pets")),
  ).rejects.toMatchObject({ code: "invalid_input" });
  expect(c.rows.size).toBe(0);
  expect(c.net.addresses).toEqual([]);
});

it("denies owned names and every owned DNS address, including mapped literals, before connecting", async () => {
  const net = network();
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve: () => Promise.resolve([publicIp, "93.184.216.10"]),
    networkPolicy: {
      deniedHostSuffixes: ["owned.example"],
      deniedCidrs: ["93.184.216.0/24", "2606:4700::/32"],
    },
  });
  for (const baseUrl of [
    "https://owned.example/v1",
    "https://child.owned.example/v1",
    "https://OWNED.example./v1",
    "https://pets.example/v1",
    "https://93.184.216.10/v1",
    "https://[::ffff:5db8:d80a]/v1",
    "https://[2606:4700::1111]/v1",
  ]) {
    await expect(
      door.send({ ...access, baseUrl }, new Request(`${baseUrl}/pets`)),
    ).rejects.toMatchObject({ code: "denied" });
  }
  expect(net.addresses).toEqual([]);
});

it("sealing twice uses distinct nonces and ciphertext", async () => {
  const c = credentialed({ kind: "bearer" });
  await c.door.seal(c.access, syntheticCredential, signal());
  const first = [...c.rows.values()][0];
  await c.door.seal(c.access, syntheticCredential, signal());
  const second = [...c.rows.values()][0];
  expect(first).toBeDefined();
  expect(second).toBeDefined();
  expect(first).not.toBe(second);
  // Maintained JSON decoder checks the envelope fields instead of asserting a parsed type.
  const schema = Schema.fromJsonString(
    Schema.Struct({ iv: Schema.String, ciphertext: Schema.String }),
  );
  const a = Schema.decodeUnknownSync(schema)(first);
  const b = Schema.decodeUnknownSync(schema)(second);
  expect(a.iv).not.toBe(b.iv);
  expect(a.ciphertext).not.toBe(b.ciphertext);
});

it("opens a fresh socket and closes it for each send on one door", async () => {
  const net = network();
  const resolve = vi.fn(() => Promise.resolve([publicIp]));
  const door = createOpenApiDoor({ connect: net.connect, resolve });
  for (const connectorId of ["first", "second"]) {
    await expect(
      door.send(
        { ...access, connectorId },
        new Request("https://pets.example/v1/pets"),
      ),
    ).resolves.toMatchObject({ status: 200 });
  }
  expect(resolve).toHaveBeenCalledTimes(2);
  expect(net.addresses).toHaveLength(2);
  expect(net.closed()).toBe(2);
});

it("rotates the active key while retained keys open existing records; retired and substituted key ids refuse", async () => {
  const c = credentialed({ kind: "bearer" });
  await c.door.seal(c.access, syntheticCredential, signal());
  const old = [...c.rows.values()][0];
  const next = Buffer.alloc(32, 12).toString("base64url");
  const rotated = createOpenApiDoor({
    ...c.options,
    custody: {
      store: c.store,
      keys: { activeKeyId: "next", keys: { test: masterKey, next } },
    },
  });
  expect(
    (await rotated.send(c.access, new Request("https://pets.example/v1/pets")))
      .status,
  ).toBe(200);
  await rotated.seal(c.access, syntheticCredential, signal());
  const schema = Schema.fromJsonString(Schema.Struct({ keyId: Schema.String }));
  expect(Schema.decodeUnknownSync(schema)([...c.rows.values()][0]).keyId).toBe(
    "next",
  );
  const retired = createOpenApiDoor({
    ...c.options,
    custody: { store: c.store, keys: { activeKeyId: "next", keys: { next } } },
  });
  if (old === undefined) throw new Error("Missing sealed fixture");
  await c.store.write(c.access, old, signal());
  await expect(
    retired.send(c.access, new Request("https://pets.example/v1/pets")),
  ).rejects.toMatchObject({ code: "denied" });
  const substituted = old.replace('"keyId":"test"', '"keyId":"alias"');
  await c.store.write(c.access, substituted, signal());
  const alias = createOpenApiDoor({
    ...c.options,
    custody: {
      store: c.store,
      keys: { activeKeyId: "alias", keys: { alias: masterKey } },
    },
  });
  await expect(
    alias.send(c.access, new Request("https://pets.example/v1/pets")),
  ).rejects.toMatchObject({ code: "denied" });
});

it.each(["constructor", "__proto__", "toString"])(
  "refuses inherited OAuth provider %s",
  async (provider) => {
    const net = network();
    const door = createOpenApiDoor({
      connect: net.connect,
      resolve: () => Promise.resolve([publicIp]),
      oauthProviders: {},
    });
    await expect(
      door.send(
        { ...access, auth: { kind: "oauth", provider, locator: "private" } },
        new Request("https://pets.example/v1/pets"),
      ),
    ).rejects.toMatchObject({ code: "oauth_not_configured" });
  },
);

it.each([
  "raw",
  "json",
  "percent",
  "percent-lower",
  "base64",
  "base64url",
  "bearer",
])(
  "redacts the %s credential encoding before returning an Agent result",
  async (form) => {
    const secret = 'abc/def"x?y';
    let echoed: string;
    switch (form) {
      case "json":
        echoed = JSON.stringify(secret).slice(1, -1);
        break;
      case "percent":
        echoed = encodeURIComponent(secret);
        break;
      case "percent-lower":
        echoed = encodeURIComponent(secret).toLowerCase();
        break;
      case "base64":
        echoed = Buffer.from(secret).toString("base64");
        break;
      case "base64url":
        echoed = Buffer.from(secret).toString("base64url");
        break;
      case "bearer":
        echoed = `Bearer ${secret}`;
        break;
      default:
        echoed = secret;
    }
    const c = credentialed({ kind: "bearer" });
    await c.door.seal(c.access, secret, signal());
    const body = `before ${echoed} after`;
    const net = network(
      `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Key: ${echoed}\r\nContent-Length: ${String(encode.encode(body).byteLength)}\r\n\r\n${body}`,
    );
    const response = await createOpenApiDoor({
      ...c.options,
      connect: net.connect,
    }).send(c.access, new Request("https://pets.example/v1/pets"));
    expect(await response.text()).toBe("before [REDACTED] after");
    expect([...response.headers]).toEqual([["content-type", "text/plain"]]);
  },
);

it("denies owned hostnames independently of the resolved address and allows a different suffix", async () => {
  const net = network();
  const resolve = vi.fn(() => Promise.resolve([publicIp]));
  const door = createOpenApiDoor({
    connect: net.connect,
    resolve,
    networkPolicy: { deniedHostSuffixes: ["owned.example"] },
  });
  for (const baseUrl of [
    "https://owned.example/v1",
    "https://child.owned.example/v1",
    "https://OWNED.example./v1",
  ]) {
    await expect(
      door.send({ ...access, baseUrl }, new Request(`${baseUrl}/pets`)),
    ).rejects.toMatchObject({ code: "denied" });
  }
  expect(resolve).not.toHaveBeenCalled();
  expect(net.addresses).toEqual([]);
  const baseUrl = "https://not-owned.example/v1";
  expect(
    (await door.send({ ...access, baseUrl }, new Request(`${baseUrl}/pets`)))
      .status,
  ).toBe(200);
});
