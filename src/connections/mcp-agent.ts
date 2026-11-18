import {
  ConnectionsError,
  type ConnectionProjection,
  type EgressRef,
  type NarrowFetch,
  type ConnectionSubject,
} from "./contract.js";

/** One owner-completed request as plain data, so it can cross a Durable Object RPC boundary. */
export type McpRequestData = Readonly<{
  url: string;
  method: string;
  headers: readonly (readonly [string, string])[];
  body: ArrayBuffer | null;
}>;
/** A refusal crosses RPC as data: a stable code, never a message. */
export type McpRefusal = Readonly<{ error: string }>;

export async function mcpRequestData(
  request: Request,
): Promise<McpRequestData> {
  return {
    url: request.url,
    method: request.method,
    headers: [...request.headers],
    body: request.body === null ? null : await request.arrayBuffer(),
  };
}

/**
 * Complete one subject's request on the owner side, the only place a
 * credential opens. The owner builds the request, so a URL it cannot carry
 * is a refusal like any other. A refusal comes back as a code, never a thrown message.
 */
export async function answerEgressRequest(
  egress: (subject: ConnectionSubject, ref: EgressRef) => NarrowFetch,
  subject: ConnectionSubject,
  ref: EgressRef,
  data: McpRequestData,
): Promise<Response | McpRefusal> {
  try {
    const init: RequestInit = {
      method: data.method,
      headers: data.headers.map(([name, value]) => [name, value]),
      redirect: "manual",
    };
    if (data.body !== null) init.body = data.body;
    return await egress(subject, ref)(data.url, init);
  } catch (cause) {
    if (cause instanceof ConnectionsError) return { error: cause.code };
    throw cause;
  }
}

/**
 * The Agent half of MCP: the servers a projection grants, and a fetch that is
 * completed by the owner. Spread into the host's Knapsack MCP source; no
 * header, token or locator is ever held on this side.
 */
export function mcpAgentSource(input: {
  read: () => Promise<ConnectionProjection>;
  fetch: (ref: EgressRef, request: Request) => Promise<Response>;
}) {
  const refs = new Map<string, EgressRef>();
  return {
    read: async () => {
      const granted = await input.read();
      refs.clear();
      const servers = granted.connections.flatMap((connection) => {
        if (connection.surface.kind !== "mcp") return [];
        refs.set(new URL(connection.surface.url).href, {
          connectionId: connection.connectionId,
          grantVersion: connection.grantVersion,
        });
        return [
          {
            id: `mcp.${connection.connectionId}`,
            name: connection.name,
            url: new URL(connection.surface.url),
          },
        ];
      });
      return {
        // Secret-free: ids, versions and endpoints.
        version: JSON.stringify(
          granted.connections.map((c) => [
            c.connectionId,
            c.grantVersion,
            c.authorityVersion,
          ]),
        ),
        servers,
      };
    },
    fetch: (url: string | URL, init?: RequestInit): Promise<Response> => {
      const request = new Request(url, init);
      const ref = refs.get(request.url);
      return ref === undefined
        ? Promise.reject(new Error("MCP server is not connected"))
        : input.fetch(ref, request);
    },
  };
}
