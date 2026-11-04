import * as Schema from "effect/Schema";
import { assertPublicHostName } from "../model-key-network.js";
import type { createPublicEgressPolicy } from "../public-egress-policy.js";
import { ConnectionsError, type Tools } from "./contract.js";

const bodyLimit = 256 * 1024;
const owned = ["authorization", "proxy-authorization", "cookie"];
const jsonValue = Schema.decodeUnknownSync(
  Schema.fromJsonString(Schema.Unknown),
);
const toolCall = Schema.decodeUnknownSync(
  Schema.Struct({ name: Schema.String }),
);

export type Endpoint = Readonly<{ kind: "mcp" | "openapi"; url: string }>;

/** One request, one verdict. The caller holds the grant; this proves the request stays inside it. */
export async function admitRequest(
  endpoint: Endpoint,
  tools: Tools,
  request: Request,
  policy: ReturnType<typeof createPublicEgressPolicy>,
): Promise<Request> {
  const target = new URL(request.url);
  const base = new URL(endpoint.url);
  const inside =
    endpoint.kind === "mcp"
      ? target.href === base.href
      : target.origin === base.origin &&
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
