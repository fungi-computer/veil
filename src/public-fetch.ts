export { validatePublicEgressPolicyEntries } from "./public-egress-policy.js";
import {
  createPublicEgressPolicy,
  type PublicEgressPolicy,
} from "./public-egress-policy.js";
export {
  createPublicEgressPolicy,
  type PublicEgressPolicy,
} from "./public-egress-policy.js";
import { Buffer } from "node:buffer";
import { HTTPParser } from "http-parser-js";
import { VeilError } from "./index.js";
import { bestEffortCleanup } from "./best-effort-cleanup.js";
import {
  createDnsOverHttpsResolver,
  resolvePublicAddresses,
  type HostResolver,
} from "./model-key-network.js";

/**
 * Veil's public-web door: an anonymous GET to a public URL, with no
 * credential, from the one sanctioned egress. The name is resolved once,
 * every answer must be public unicast (IPv4 and IPv6; loopback, private,
 * link-local, metadata and address-embedding ranges are refused), and the
 * connection is made to exactly one of those checked addresses. Host and TLS
 * server name stay the URL's own, so certificates verify against the name the
 * caller asked for while a second lookup can never move the connection (DNS
 * rebinding). Each call is one hop: it never follows a redirect, so the
 * caller's next hop resolves and is checked again.
 */

/** A connected socket, shaped like the Workers `cloudflare:sockets` Socket. */
export type PublicSocket = Readonly<{
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened: Promise<unknown>;
  startTls: (
    options: Readonly<{ expectedServerHostname: string }>,
  ) => PublicSocket;
  close: () => Promise<void>;
}>;

/**
 * The host's socket primitive. Veil calls it only with an address it checked,
 * never with a name, so no resolver sits between the check and the connection.
 */
export type PublicConnect = (
  address: Readonly<{ hostname: string; port: number }>,
  options: Readonly<{
    secureTransport: "off" | "starttls";
    allowHalfOpen: false;
  }>,
) => PublicSocket;

/** One anonymous GET. Only these two request headers can ever be sent. */
export type PublicGetRequest = Readonly<{
  url: URL;
  accept: string;
  userAgent: string;
  signal: AbortSignal;
}>;
export type PublicGet = (request: PublicGetRequest) => Promise<Response>;
export type PublicFetchDoor = Readonly<{ get: PublicGet }>;

/** Where a refusal came from; the message never carries remote bytes. */
export type PublicFetchStage = "address" | "dns" | "connect" | "response";

export class PublicFetchError extends VeilError {
  public constructor(
    code: VeilError["code"],
    public readonly stage: PublicFetchStage,
  ) {
    super(code);
    this.name = "PublicFetchError";
  }
}

/** Response status line and headers must fit here before the body starts. */
const MAX_HEADER_BYTES = 64 * 1024;
const HEADER_SLICE_BYTES = 4 * 1024;
/** Checked addresses tried in order when a connection cannot be opened. */
const MAX_ADDRESSES = 4;
const encoder = new TextEncoder();

type Destination = Readonly<{
  secure: boolean;
  hostname: string;
  port: number;
}>;

function destination(url: URL): Destination {
  if (url.protocol !== "https:" && url.protocol !== "http:")
    throw new PublicFetchError("denied", "address");
  if (url.username !== "" || url.password !== "")
    throw new PublicFetchError("denied", "address");
  const secure = url.protocol === "https:";
  return {
    secure,
    hostname: url.hostname,
    port: url.port === "" ? (secure ? 443 : 80) : Number(url.port),
  };
}

function headerValue(value: string): string {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code < 0x20 || code === 0x7f)
      throw new PublicFetchError("invalid_input", "address");
  }
  return value;
}

/** Private HTTP adapter shared by anonymous GET and the OpenAPI policy door. */
export type PublicHttpRequest = Readonly<{
  url: URL;
  method: string;
  headers: Headers;
  body: Uint8Array;
  signal: AbortSignal;
}>;

function requestBytes(request: PublicHttpRequest): Uint8Array {
  const { url } = request;
  // The URL parser percent-encodes the path and query, so neither can carry a
  // line break; `host` is the URL's own authority.
  const head = encoder.encode(
    [
      `${request.method} ${url.pathname}${url.search} HTTP/1.1`,
      `Host: ${url.host}`,
      ...Array.from(
        request.headers,
        ([name, value]) => `${name}: ${headerValue(value)}`,
      ),
      "Accept-Encoding: identity",
      "Connection: close",
      ...(request.body.byteLength > 0 ||
      !["GET", "HEAD"].includes(request.method)
        ? [`Content-Length: ${String(request.body.byteLength)}`]
        : []),
      "",
      "",
    ].join("\r\n"),
  );
  if (head.byteLength > MAX_HEADER_BYTES)
    throw new PublicFetchError("invalid_input", "address");
  const bytes = new Uint8Array(head.byteLength + request.body.byteLength);
  bytes.set(head);
  bytes.set(request.body, head.byteLength);
  return bytes;
}

/** Wait for the socket to open, giving up when the call is cancelled. */
async function opened(
  socket: PublicSocket,
  signal: AbortSignal,
): Promise<void> {
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => {
      reject(new PublicFetchError("cancelled", "connect"));
    };
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    await Promise.race([socket.opened, aborted]);
  } finally {
    if (onAbort !== undefined) signal.removeEventListener("abort", onAbort);
  }
}

/** Open a connection to the first checked address that accepts one. */
async function connectChecked(
  connect: PublicConnect,
  addresses: readonly string[],
  to: Destination,
  signal: AbortSignal,
): Promise<PublicSocket> {
  for (const hostname of addresses.slice(0, MAX_ADDRESSES)) {
    let socket: PublicSocket | undefined;
    try {
      signal.throwIfAborted();
      socket = connect(
        { hostname, port: to.port },
        {
          secureTransport: to.secure ? "starttls" : "off",
          allowHalfOpen: false,
        },
      );
      await opened(socket, signal);
      return to.secure
        ? socket.startTls({
            expectedServerHostname: to.hostname.replace(/^\[|\]$/gu, ""),
          })
        : socket;
    } catch {
      await bestEffortCleanup(
        "public-fetch-socket",
        () => socket?.close() ?? Promise.resolve(),
      );
      if (signal.aborted) throw new PublicFetchError("cancelled", "connect");
    }
  }
  throw new PublicFetchError("unavailable", "connect");
}

const bodylessStatuses = new Set([204, 205, 304]);
/** Headers describing wire framing, which the parsed Response no longer has. */
const framingHeaders = new Set([
  "transfer-encoding",
  "connection",
  "keep-alive",
]);

type Head = Readonly<{ status: number; headers: Headers }>;

function refusedResponse(): PublicFetchError {
  return new PublicFetchError("invalid_response", "response");
}

function decodeHead(info: {
  statusCode: number;
  headers: readonly string[];
  upgrade: boolean;
}): Head {
  if (info.upgrade || info.statusCode < 200) throw refusedResponse();
  const headers = new Headers();
  let transferEncodings = 0;
  for (let index = 0; index + 1 < info.headers.length; index += 2) {
    const name = (info.headers[index] ?? "").toLowerCase();
    const value = info.headers[index + 1] ?? "";
    if (name === "transfer-encoding") {
      // The parser frames only a bare `chunked`; anything layered is unreadable.
      transferEncodings += 1;
      if (transferEncodings > 1 || value.toLowerCase() !== "chunked")
        throw refusedResponse();
    }
    if (name === "content-length" && !/^[0-9]{1,15}$/u.test(value))
      throw refusedResponse();
    // Compressed bodies are never requested; an unrequested one is not text.
    if (
      name === "content-encoding" &&
      value.trim() !== "" &&
      value.trim().toLowerCase() !== "identity"
    )
      throw refusedResponse();
    if (framingHeaders.has(name)) continue;
    try {
      headers.append(name, value);
    } catch {
      throw refusedResponse();
    }
  }
  return { status: info.statusCode, headers };
}

/**
 * Write the request and read one HTTP/1.1 response from `socket`. The
 * maintained parser frames it (status line, headers, content-length, chunked,
 * read-to-close). The body stays a pull stream, so a reader that cancels
 * closes the socket and cancelling `signal` closes it too.
 */
async function exchange(
  socket: PublicSocket,
  request: PublicHttpRequest,
): Promise<Response> {
  const { signal } = request;
  const reader = socket.readable.getReader();
  const parser = new HTTPParser(HTTPParser.RESPONSE);
  parser.maxHeaderSize = MAX_HEADER_BYTES;
  const pending: Uint8Array[] = [];
  let head: Head | undefined;
  const state = { complete: false };
  const finished = () => state.complete;
  let disposed = false;

  const dispose = async () => {
    if (disposed) return;
    disposed = true;
    signal.removeEventListener("abort", onAbort);
    await Promise.allSettled([reader.cancel(), socket.close()]);
  };
  function onAbort() {
    void dispose();
  }
  signal.addEventListener("abort", onAbort, { once: true });

  // One request per connection: once the first response is complete, whatever
  // else the peer sends is not part of it.
  parser[HTTPParser.kOnHeadersComplete] = (info) => {
    if (state.complete) return 1;
    head = decodeHead(info);
    return bodylessStatuses.has(info.statusCode) || request.method === "HEAD"
      ? 1
      : undefined;
  };
  parser[HTTPParser.kOnBody] = (chunk, offset, length) => {
    if (!state.complete && length > 0)
      pending.push(Uint8Array.from(chunk.subarray(offset, offset + length)));
  };
  parser[HTTPParser.kOnMessageComplete] = () => {
    state.complete = true;
  };

  /** Read one socket chunk into the parser; false once the peer has closed. */
  const advance = async (): Promise<boolean> => {
    let next: Awaited<ReturnType<typeof reader.read>>;
    try {
      next = await reader.read();
    } catch {
      throw new PublicFetchError(
        signal.aborted ? "cancelled" : "unavailable",
        "response",
      );
    }
    if (next.done) {
      if (parser.finish() instanceof Error && !state.complete)
        throw refusedResponse();
      return false;
    }
    const { buffer, byteOffset, byteLength } = next.value;
    // The parser measures its header cap after each call, so feed small slices
    // until the head is read; a body may then arrive whole.
    for (let start = 0; start < byteLength;) {
      const end =
        head === undefined
          ? Math.min(start + HEADER_SLICE_BYTES, byteLength)
          : byteLength;
      const parsed = parser.execute(
        Buffer.from(buffer, byteOffset + start, end - start),
      );
      if (parsed instanceof Error && !state.complete) throw refusedResponse();
      start = end;
    }
    return true;
  };

  try {
    try {
      const writer = socket.writable.getWriter();
      await writer.write(requestBytes(request));
      writer.releaseLock();
    } catch {
      throw new PublicFetchError(
        signal.aborted ? "cancelled" : "unavailable",
        "connect",
      );
    }
    while (head === undefined) {
      if (!(await advance())) throw refusedResponse();
    }
  } catch (error) {
    await dispose();
    throw error;
  }

  const { status, headers } = head;
  if (bodylessStatuses.has(status) || request.method === "HEAD") {
    await dispose();
    return new Response(null, { status, headers });
  }
  const body = new ReadableStream<Uint8Array>({
    pull: async (controller) => {
      try {
        for (;;) {
          const chunk = pending.shift();
          if (chunk !== undefined) {
            controller.enqueue(chunk);
            return;
          }
          if (state.complete) {
            await dispose();
            controller.close();
            return;
          }
          const more = await advance();
          // `advance` may have completed the response, even at end of stream.
          if (!more && !finished()) throw refusedResponse();
        }
      } catch (error) {
        await dispose();
        throw error;
      }
    },
    cancel: dispose,
  });
  try {
    return new Response(body, { status, headers });
  } catch {
    await dispose();
    throw refusedResponse();
  }
}

/**
 * The public-fetch door. `resolve` is the only name lookup and runs once per
 * call; `connect` is handed only the addresses that lookup returned and
 * Veil checked.
 */
export type PublicHttpDoor = Readonly<{
  send: (request: PublicHttpRequest) => Promise<Response>;
}>;

export function createPublicHttp(
  options: Readonly<{
    connect: PublicConnect;
    resolve: HostResolver;
    networkPolicy?: PublicEgressPolicy;
  }>,
): PublicHttpDoor {
  const policy = createPublicEgressPolicy(options.networkPolicy);
  return {
    send: async (request) => {
      const to = destination(request.url);
      let addresses: readonly string[];
      try {
        policy.destination(request.url);
        addresses = await resolvePublicAddresses(
          to.hostname,
          options.resolve,
          request.signal,
        );
        policy.addresses(addresses);
      } catch (error) {
        if (error instanceof VeilError && error.code === "denied")
          throw new PublicFetchError("denied", "address");
        throw new PublicFetchError(
          request.signal.aborted ? "cancelled" : "unavailable",
          "dns",
        );
      }
      const socket = await connectChecked(
        options.connect,
        addresses,
        to,
        request.signal,
      );
      return await exchange(socket, request);
    },
  };
}

/** Anonymous GET keeps its existing two-header authority. */
export function createPublicFetch(
  options: Readonly<{
    connect: PublicConnect;
    resolve: HostResolver;
    networkPolicy?: PublicEgressPolicy;
  }>,
): PublicFetchDoor {
  const http = createPublicHttp({
    ...options,
    networkPolicy: {
      ...options.networkPolicy,
      // The anonymous public-web contract includes ordinary HTTP. Extra ports remain host-only.
      extraPorts: [80, ...(options.networkPolicy?.extraPorts ?? [])],
    },
  });
  return {
    get: async (request) => {
      let headers: Headers;
      try {
        headers = new Headers({
          Accept: request.accept,
          "User-Agent": request.userAgent,
        });
      } catch {
        throw new PublicFetchError("invalid_input", "address");
      }
      return http.send({
        url: request.url,
        method: "GET",
        headers,
        body: new Uint8Array(),
        signal: request.signal,
      });
    },
  };
}

/**
 * The production door: the host's socket primitive plus its `fetch`, used only
 * for the DNS-over-HTTPS lookup of the one resolution each call makes.
 */
export function configuredPublicFetch(
  options: Readonly<{
    connect: PublicConnect;
    fetch: typeof fetch;
    networkPolicy?: PublicEgressPolicy;
  }>,
): PublicFetchDoor {
  return createPublicFetch({
    connect: options.connect,
    resolve: createDnsOverHttpsResolver(options.fetch),
    networkPolicy: options.networkPolicy ?? {},
  });
}
