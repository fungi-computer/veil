import type { OpenApiOperation } from "@fungi.computer/forage/openapi";
import * as Schema from "effect/Schema";
import { z } from "zod";
import { ConnectionsError, type Tools } from "./contract.js";

/** Stored operations are decoded again on every use; the digest binds what the owner approved. */
export async function decodeTable(
  stored: readonly unknown[] | null | undefined,
) {
  try {
    // Forage loads on first use, never at Team startup.
    const { parseOpenApiTable } =
      await import("@fungi.computer/forage/openapi");
    return await parseOpenApiTable(stored);
  } catch (cause) {
    throw new ConnectionsError("unavailable", { cause });
  }
}

/** Whether a grant admits one operation by name and stored effect. */
export function admits(
  tools: Tools,
  operation: Pick<OpenApiOperation, "name" | "effect">,
): boolean {
  if (tools === "all") return true;
  if (Array.isArray(tools)) return tools.includes(operation.name);
  return operation.effect === "read";
}

function hasControlCharacters(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) return true;
  }
  return false;
}

/** Builds only a stored operation's request; the core alone attaches the credential. */
export async function operationRequest(
  baseUrl: string,
  operation: OpenApiOperation,
  rawInput: unknown,
): Promise<Request> {
  const { jsonSchemaToZod } = await import("@fungi.computer/forage");
  try {
    const input = z
      .record(z.string(), z.json())
      .parse(jsonSchemaToZod(operation.input).parse(rawInput));
    const base = new URL(baseUrl);
    let path = operation.path;
    const headers = new Headers();
    const query = new URLSearchParams();
    for (const parameter of operation.parameters) {
      const value = input[parameter.name];
      if (value === undefined || value === null) continue;
      const scalar = z
        .union([z.string(), z.number(), z.boolean()])
        .parse(value);
      if (parameter.in === "path") {
        const segment = String(scalar);
        if (
          !segment ||
          segment === "." ||
          segment === ".." ||
          segment.includes("/") ||
          segment.includes("\\") ||
          hasControlCharacters(segment) ||
          /%(?:2e|2f|5c|25)/iu.test(segment)
        )
          throw new ConnectionsError("invalid_input");
        path = path.replace(`{${parameter.name}}`, encodeURIComponent(segment));
      } else if (parameter.in === "query")
        query.set(parameter.name, String(scalar));
      else headers.set(parameter.name, String(scalar));
    }
    const basePath = `${base.pathname.replace(/\/$/u, "")}/`;
    const url = new URL(`${basePath}${path.slice(1)}`, base.origin);
    if (url.origin !== base.origin || !url.pathname.startsWith(basePath))
      throw new ConnectionsError("invalid_input");
    url.search = query.toString();
    const body =
      input.body === undefined ? undefined : JSON.stringify(input.body);
    if (body !== undefined) headers.set("Content-Type", "application/json");
    const init: RequestInit = {
      method: operation.method,
      headers,
      redirect: "error",
    };
    if (body !== undefined) init.body = body;
    return new Request(url, init);
  } catch (cause) {
    if (cause instanceof ConnectionsError) throw cause;
    throw new ConnectionsError("invalid_input", { cause });
  }
}

/** The stored output schema is the contract for what an Agent may see. */
export async function operationOutput(
  operation: OpenApiOperation,
  text: string,
) {
  const { jsonSchemaToZod } = await import("@fungi.computer/forage");
  try {
    return z
      .json()
      .parse(
        jsonSchemaToZod(operation.output).parse(
          Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Unknown))(text),
        ),
      );
  } catch (cause) {
    throw new ConnectionsError("invalid_response", { cause });
  }
}

const responseLimit = 4 * 1024 * 1024;
/** A response body as text, refusing more than the response cap. */
export async function boundedText(response: Response): Promise<string> {
  const reader: ReadableStreamDefaultReader<Uint8Array> | undefined =
    response.body?.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let size = 0;
  let text = "";
  for (;;) {
    const next = await reader?.read();
    if (next === undefined || next.done) break;
    size += next.value.byteLength;
    if (size > responseLimit) {
      await reader?.cancel();
      throw new ConnectionsError("too_large");
    }
    text += decoder.decode(next.value, { stream: true });
  }
  return text + decoder.decode();
}
