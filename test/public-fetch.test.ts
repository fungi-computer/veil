import { describe, expect, it } from "vitest";
import {
  createPublicFetch,
  PublicFetchError,
  type PublicConnect,
  type PublicSocket,
} from "../src/public-fetch.js";

const PUBLIC = "93.184.215.14";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

type Wire = Readonly<{
  connects: { hostname: string; port: number; secureTransport: string }[];
  tlsNames: string[];
  requests: string[];
  closed: () => number;
}>;

/**
 * A socket whose peer answers the first request with `chunks`, one socket read
 * each, then closes. Nothing here opens a real connection.
 */
function network(
  respond: (request: string, hostname: string) => string[],
  options: Readonly<{ refuse?: (hostname: string) => boolean }> = {},
) {
  const connects: Wire["connects"] = [];
  const tlsNames: string[] = [];
  const requests: string[] = [];
  let closed = 0;
  const connect: PublicConnect = (address, { secureTransport }) => {
    connects.push({ ...address, secureTransport });
    if (options.refuse?.(address.hostname) === true) {
      return {
        readable: new ReadableStream<Uint8Array>(),
        writable: new WritableStream<Uint8Array>(),
        get opened() {
          return Promise.reject(new Error("refused"));
        },
        startTls: () => {
          throw new Error("not open");
        },
        close: () => {
          closed += 1;
          return Promise.resolve();
        },
      };
    }
    let wrote: () => void = () => undefined;
    const requested = new Promise<void>((resolve) => {
      wrote = resolve;
    });
    const pieces: string[] = [];
    let started = false;
    const socket: PublicSocket = {
      readable: new ReadableStream<Uint8Array>({
        pull: async (controller) => {
          await requested;
          if (!started) {
            started = true;
            pieces.push(...respond(requests.at(-1) ?? "", address.hostname));
          }
          const next = pieces.shift();
          if (next === undefined) controller.close();
          else controller.enqueue(encoder.encode(next));
        },
      }),
      writable: new WritableStream<Uint8Array>({
        write: (bytes) => {
          requests.push(decoder.decode(bytes));
          wrote();
        },
      }),
      opened: Promise.resolve({}),
      startTls: ({ expectedServerHostname }) => {
        tlsNames.push(expectedServerHostname);
        return socket;
      },
      close: () => {
        closed += 1;
        return Promise.resolve();
      },
    };
    return socket;
  };
  return {
    connect,
    wire: { connects, tlsNames, requests, closed: () => closed },
  };
}

const ok = (body: string, extra = "") =>
  `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${String(encoder.encode(body).byteLength)}\r\n${extra}\r\n${body}`;

function door(
  net: ReturnType<typeof network>,
  resolve: (hostname: string) => readonly string[] = () => [PUBLIC],
) {
  const lookups: string[] = [];
  const { get } = createPublicFetch({
    connect: net.connect,
    resolve: (hostname) => {
      lookups.push(hostname);
      return Promise.resolve(resolve(hostname));
    },
  });
  const request = (url: string, signal = new AbortController().signal) =>
    get({
      url: new URL(url),
      accept: "text/plain",
      userAgent: "test-agent/1",
      signal,
    });
  return { request, lookups };
}

describe("public fetch door: one resolution, one pinned address", () => {
  it("connects to the address it checked with the URL's own Host and TLS name", async () => {
    const net = network(() => [ok("hello")]);
    const { request, lookups } = door(net);
    const response = await request("https://docs.example.com/a/b?q=1");
    expect(await response.text()).toBe("hello");
    expect(lookups).toEqual(["docs.example.com"]);
    expect(net.wire.connects).toEqual([
      { hostname: PUBLIC, port: 443, secureTransport: "starttls" },
    ]);
    expect(net.wire.tlsNames).toEqual(["docs.example.com"]);
    expect(net.wire.requests[0]).toBe(
      [
        "GET /a/b?q=1 HTTP/1.1",
        "Host: docs.example.com",
        "accept: text/plain",
        "user-agent: test-agent/1",
        "Accept-Encoding: identity",
        "Connection: close",
        "",
        "",
      ].join("\r\n"),
    );
  });

  it("sends plain HTTP to its ordinary port and keeps the hostname in Host", async () => {
    const net = network(() => [ok("x")]);
    const { request } = door(net);
    await request("http://docs.example.com/");
    expect(net.wire.connects).toEqual([
      { hostname: PUBLIC, port: 80, secureTransport: "off" },
    ]);
    expect(net.wire.tlsNames).toEqual([]);
    expect(net.wire.requests[0]).toContain("Host: docs.example.com\r\n");
  });

  it("is not moved by a second lookup that answers inward (DNS rebinding)", async () => {
    const net = network(() => [ok("first")]);
    let calls = 0;
    const { request, lookups } = door(net, () => {
      calls += 1;
      return calls === 1 ? [PUBLIC] : ["127.0.0.1"];
    });
    // The one lookup of this call is public, so the connection goes there and
    // nothing asks again that could answer 127.0.0.1 in between.
    await (await request("https://rebind.example.com/")).text();
    expect(lookups).toHaveLength(1);
    expect(net.wire.connects.map(({ hostname }) => hostname)).toEqual([PUBLIC]);
    // The next hop is a new call: it resolves again, gets the inward answer and
    // is refused without a connection.
    await expect(
      request("https://rebind.example.com/next"),
    ).rejects.toMatchObject({ code: "denied", stage: "address" });
    expect(lookups).toHaveLength(2);
    expect(net.wire.connects).toHaveLength(1);
  });

  it("does not follow a public response redirect to a private address", async () => {
    const net = network(() => [
      "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\n\r\n",
    ]);
    const { request, lookups } = door(net);
    const response = await request("https://rebind.example.com/");
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "http://169.254.169.254/latest/meta-data/",
    );
    expect(lookups).toEqual(["rebind.example.com"]);
    expect(net.wire.connects.map(({ hostname }) => hostname)).toEqual([PUBLIC]);
  });

  it.each([
    ["loopback", ["127.0.0.1"]],
    ["mixed public and private", [PUBLIC, "10.0.0.5"]],
    ["metadata", ["169.254.169.254"]],
    ["carrier-grade NAT", ["100.64.0.9"]],
    ["IPv6 loopback", ["::1"]],
    ["IPv6 unspecified", ["::"]],
    ["IPv6 link-local", ["fe80::1"]],
    ["IPv6 unique local", ["fd00::1"]],
    ["IPv4-mapped loopback", ["::ffff:127.0.0.1"]],
    ["IPv4-mapped loopback in hex", ["::ffff:7f00:1"]],
    ["IPv4-mapped private", ["::ffff:10.0.0.1"]],
    ["IPv4-compatible loopback", ["::127.0.0.1"]],
    ["NAT64 loopback", ["64:ff9b::7f00:1"]],
    ["6to4 loopback", ["2002:7f00:1::1"]],
    ["Teredo", ["2001:0:4136:e378:8000:63bf:3fff:fdd2"]],
    ["an unparseable answer", ["not-an-address"]],
    ["a zone-scoped answer", ["fe80::1%eth0"]],
  ])(
    "refuses a name that resolves to %s before any connection",
    async (_name, answers) => {
      const net = network(() => [ok("never")]);
      const { request } = door(net, () => answers);
      await expect(
        request("https://sneaky.example.com/"),
      ).rejects.toMatchObject({
        code: "denied",
      });
      expect(net.wire.connects).toEqual([]);
    },
  );

  it.each([
    "http://127.0.0.1/",
    "http://127.1/",
    "http://0x7f.0.0.1/",
    "http://2130706433/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    "http://[::ffff:10.0.0.1]/",
    "http://[fe80::1]/",
    "http://10.0.0.8/",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
    "http://service.localhost/",
    "http://intranet/",
    "http://printer.local/",
  ])(
    "refuses the literal or inward host %s without resolving or connecting",
    async (url) => {
      const net = network(() => [ok("never")]);
      const { request, lookups } = door(net);
      await expect(request(url)).rejects.toMatchObject({ code: "denied" });
      expect(lookups).toEqual([]);
      expect(net.wire.connects).toEqual([]);
    },
  );

  it("connects to a public literal without a lookup, naming the literal for TLS", async () => {
    const net = network(() => [ok("lit")]);
    const { request, lookups } = door(net);
    await request("https://[2606:4700::1111]/");
    expect(lookups).toEqual([]);
    expect(net.wire.connects[0]).toMatchObject({
      hostname: "2606:4700:0:0:0:0:0:1111",
      port: 443,
    });
    expect(net.wire.tlsNames).toEqual(["2606:4700::1111"]);
    expect(net.wire.requests[0]).toContain("Host: [2606:4700::1111]\r\n");
  });

  it("refuses schemes other than http(s) and URLs carrying credentials", async () => {
    const net = network(() => [ok("never")]);
    const { request } = door(net);
    for (const url of [
      "file:///etc/passwd",
      "ftp://files.example.com/",
      "https://user:secret@site.example.com/",
    ])
      await expect(request(url), url).rejects.toMatchObject({ code: "denied" });
    expect(net.wire.connects).toEqual([]);
  });

  it("refuses a request header that could carry a second header", async () => {
    const net = network(() => [ok("never")]);
    const { get } = createPublicFetch({
      connect: net.connect,
      resolve: () => Promise.resolve([PUBLIC]),
    });
    await expect(
      get({
        url: new URL("https://docs.example.com/"),
        accept: "text/plain\r\nAuthorization: Bearer x",
        userAgent: "test",
        signal: new AbortController().signal,
      }),
    ).rejects.toBeInstanceOf(PublicFetchError);
    expect(net.wire.requests).toEqual([]);
  });

  it("types a lookup that fails or answers nothing as a DNS failure", async () => {
    const net = network(() => [ok("never")]);
    const failing = createPublicFetch({
      connect: net.connect,
      resolve: () => Promise.reject(new Error("servfail")),
    });
    const url = new URL("https://gone.example.com/");
    const signal = new AbortController().signal;
    await expect(
      failing.get({ url, accept: "*/*", userAgent: "t", signal }),
    ).rejects.toMatchObject({ code: "unavailable", stage: "dns" });
    await expect(door(net, () => []).request(url.href)).rejects.toMatchObject({
      code: "unavailable",
      stage: "dns",
    });
    expect(net.wire.connects).toEqual([]);
  });

  it("falls through to the next checked address only when a connection cannot open", async () => {
    const second = "93.184.215.15";
    const net = network(() => [ok("second")], {
      refuse: (hostname) => hostname === PUBLIC,
    });
    const { request } = door(net, () => [PUBLIC, second]);
    expect(await (await request("http://two.example.com/")).text()).toBe(
      "second",
    );
    expect(net.wire.connects.map(({ hostname }) => hostname)).toEqual([
      PUBLIC,
      second,
    ]);
    const dead = network(() => [], { refuse: () => true });
    await expect(
      door(dead, () => [PUBLIC, second]).request("http://two.example.com/"),
    ).rejects.toMatchObject({ code: "unavailable", stage: "connect" });
  });
});

describe("public fetch door: one HTTP/1.1 response", () => {
  it("does not follow a redirect and hands back its Location", async () => {
    const net = network(() => [
      "HTTP/1.1 302 Found\r\nLocation: http://192.168.1.1/admin\r\nContent-Length: 0\r\n\r\n",
    ]);
    const { request } = door(net);
    const response = await request("https://short.example.com/go");
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("http://192.168.1.1/admin");
    expect(net.wire.connects).toHaveLength(1);
  });

  it("reads a chunked body split across socket reads", async () => {
    const net = network(() => [
      "HTTP/1.1 200 OK\r\nTransfer-Enc",
      "oding: chunked\r\nContent-Type: text/plain\r\n\r\n5\r\nhel",
      "lo\r\n6\r\n wor",
      "ld\r\n0\r\n\r\n",
    ]);
    const response = await door(net).request("https://c.example.com/");
    expect(response.headers.get("transfer-encoding")).toBeNull();
    expect(await response.text()).toBe("hello world");
    expect(net.wire.closed()).toBeGreaterThan(0);
  });

  it("reads a body that ends when the peer closes", async () => {
    const net = network(() => [
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nuntil ",
      "eof",
    ]);
    const response = await door(net).request("https://eof.example.com/");
    expect(await response.text()).toBe("until eof");
  });

  it("hands back no body for 204 and 304", async () => {
    const net = network(() => ["HTTP/1.1 204 No Content\r\n\r\n"]);
    const response = await door(net).request("https://none.example.com/");
    expect(response.status).toBe(204);
    expect(response.body).toBeNull();
  });

  it("ignores bytes the peer sends after a complete response", async () => {
    const net = network(() => [
      `${ok("one")}HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nextra`,
    ]);
    const response = await door(net).request("https://more.example.com/");
    expect(await response.text()).toBe("one");
  });

  it("fails the body read when the peer closes before Content-Length", async () => {
    const net = network(() => [
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 50\r\n\r\nshort",
    ]);
    const response = await door(net).request("https://cut.example.com/");
    await expect(response.text()).rejects.toBeInstanceOf(PublicFetchError);
  });

  it.each([
    ["garbage instead of a status line", ["NOT HTTP\r\n\r\n"]],
    ["a connection that closes without a response", []],
    ["an informational status", ["HTTP/1.1 101 Switching\r\n\r\n"]],
    [
      "a layered transfer coding",
      ["HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"],
    ],
    [
      "a non-numeric Content-Length",
      ["HTTP/1.1 200 OK\r\nContent-Length: ten\r\n\r\nabc"],
    ],
    [
      "an unrequested content coding",
      [
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx",
      ],
    ],
    [
      "headers larger than the cap",
      ["HTTP/1.1 200 OK\r\n", `X-Big: ${"a".repeat(70 * 1024)}\r\n\r\n`],
    ],
  ])("refuses %s", async (_name, chunks) => {
    const net = network(() => chunks);
    await expect(
      door(net).request("https://odd.example.com/"),
    ).rejects.toMatchObject({ code: "invalid_response", stage: "response" });
    expect(net.wire.closed()).toBeGreaterThan(0);
  });

  it("closes the socket when the reader stops early", async () => {
    const net = network(() => [
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
      "a".repeat(1024),
      "b".repeat(1024),
    ]);
    const response = await door(net).request("https://big.example.com/");
    const reader = response.body?.getReader();
    await reader?.read();
    await reader?.cancel();
    expect(net.wire.closed()).toBeGreaterThan(0);
  });

  it("closes the socket when the call is cancelled", async () => {
    const net = network(() => [
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nstart",
    ]);
    const controller = new AbortController();
    const response = await door(net).request(
      "https://slow.example.com/",
      controller.signal,
    );
    controller.abort();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(net.wire.closed()).toBeGreaterThan(0);
    await response.body?.cancel();
  });
});
