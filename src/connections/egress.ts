import * as Schema from "effect/Schema";
import ipaddr from "ipaddr.js";
import { assertPublicHostName } from "../model-key-network.js";
import type { createPublicEgressPolicy } from "../public-egress-policy.js";
import {
  ConnectionsError,
  type Tools,
  type HttpDestinations,
} from "./contract.js";

const bodyLimit = 256 * 1024;
const owned = ["authorization", "proxy-authorization", "cookie"];
const jsonValue = Schema.decodeUnknownSync(
  Schema.fromJsonString(Schema.Unknown),
);
const toolCall = Schema.decodeUnknownSync(
  Schema.Struct({ name: Schema.String }),
);

export type Endpoint =
  | Readonly<{ kind: "mcp" | "openapi"; url: string }>
  | Readonly<{ kind: "http"; destinations: HttpDestinations }>;

/** URL and ipaddr own parsing. These refinements admit only canonical exact DNS hosts. */
export function validateDestinations(destinations: HttpDestinations): void {
  for (const rule of destinations) {
    const url = URL.parse(`https://${rule.host}`);
    if (
      url?.hostname !== rule.host ||
      url.host !== rule.host ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash ||
      rule.host.includes("*") ||
      rule.host.endsWith(".") ||
      ipaddr.isValid(
        rule.host.startsWith("[") ? rule.host.slice(1, -1) : rule.host,
      )
    )
      throw new ConnectionsError("invalid_input");
    try {
      assertPublicHostName(url.hostname);
    } catch {
      throw new ConnectionsError("invalid_input");
    }
    if (rule.pathPrefix !== undefined) {
      const path = URL.parse(rule.pathPrefix, url.href);
      if (
        !rule.pathPrefix.startsWith("/") ||
        path?.origin !== url.origin ||
        path.pathname !== rule.pathPrefix ||
        path.search ||
        path.hash
      )
        throw new ConnectionsError("invalid_input");
    }
  }
}

const insideHttp = (
  target: URL,
  method: string,
  destinations: HttpDestinations,
) =>
  target.protocol === "https:" &&
  target.port === "" &&
  destinations.some(
    (rule) =>
      target.hostname === rule.host &&
      rule.methods.some((allowed) => allowed === method) &&
      (rule.pathPrefix === undefined ||
        target.pathname === rule.pathPrefix ||
        target.pathname.startsWith(
          rule.pathPrefix.endsWith("/")
            ? rule.pathPrefix
            : `${rule.pathPrefix}/`,
        )),
  );

/** One request, one verdict. The caller holds the grant; this proves the request stays inside it. */
export async function admitRequest(
  endpoint: Endpoint,
  tools: Tools,
  request: Request,
  policy: ReturnType<typeof createPublicEgressPolicy>,
): Promise<Request> {
  const target = new URL(request.url);
  const base = endpoint.kind === "http" ? null : new URL(endpoint.url);
  const inside =
    endpoint.kind === "http"
      ? insideHttp(target, request.method, endpoint.destinations)
      : endpoint.kind === "mcp"
        ? target.href === base?.href
        : base !== null &&
          target.origin === base.origin &&
          target.pathname.startsWith(
            base.pathname.endsWith("/") ? base.pathname : `${base.pathname}/`,
          );
  if (
    !inside ||
    request.redirect !== "error" ||
    target.username ||
    target.password ||
    owned.some((name) => request.headers.has(name))
  )
    throw new ConnectionsError("denied");
  try {
    assertPublicHostName(target.hostname);
    policy.destination(target);
  } catch (cause) {
    throw new ConnectionsError("denied", { cause });
  }
  if (request.body === null) return request;
  const bytes = await boundedBytes(request.clone());
  if (endpoint.kind === "mcp" && Array.isArray(tools)) {
    let name: string | null = null;
    // The SDK stays out of startup: it loads when a listed MCP grant first meets a body.
    const { isJSONRPCRequest, parseJSONRPCMessage } =
      await import("@modelcontextprotocol/client");
    try {
      const message = parseJSONRPCMessage(
        jsonValue(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
      );
      if (isJSONRPCRequest(message) && message.method === "tools/call")
        name = toolCall(message.params).name;
    } catch (cause) {
      throw new ConnectionsError("denied", { cause });
    }
    if (name !== null && !tools.includes(name))
      throw new ConnectionsError("denied");
  }
  return new Request(request.url, {
    method: request.method,
    headers: request.headers,
    body: bytes,
    redirect: request.redirect,
    signal: request.signal,
  });
}

/** Read the body once, stopping as soon as it passes the byte cap. */
async function boundedBytes(
  request: Request,
): Promise<Uint8Array<ArrayBuffer>> {
  const chunks: Uint8Array[] = [];
  let size = 0;
  const reader: ReadableStreamDefaultReader<Uint8Array> | undefined =
    request.body?.getReader();
  for (;;) {
    const next = await reader?.read();
    if (next === undefined || next.done) break;
    size += next.value.byteLength;
    if (size > bodyLimit) {
      await reader?.cancel();
      throw new ConnectionsError("too_large");
    }
    chunks.push(next.value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
