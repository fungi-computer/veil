import { VeilError } from "./index.js";
import { assertPublicHostName } from "./model-key-network.js";

/**
 * Write-only custody for the credential a Team gives one Agent's Vishnu world
 * seat. The token enters once through `seal`; nothing returns it. `send`
 * attaches it at final egress, so the Team, the Agent and every projection
 * hold only the private locator and the public endpoint.
 */
export type WorldSeatAccess = Readonly<{
  /** Private custody id chosen by the Team owner; never a public field. */
  locator: string;
  /** The seat's MCP endpoint, already accepted by `worldSeatEndpoint`. */
  endpoint: string;
}>;

export type WorldSeatCustodian = Readonly<{
  seal: (
    input: Readonly<{
      teamId: string;
      locator: string;
      endpoint: string;
      token: string;
    }>,
    signal: AbortSignal,
  ) => Promise<void>;
  send: (access: WorldSeatAccess, request: Request) => Promise<Response>;
  remove: (
    access: Pick<WorldSeatAccess, "locator">,
    signal: AbortSignal,
  ) => Promise<"deleted" | "absent">;
}>;

/** Longest token a seat may seal; the connection input schema bounds it too. */
export const WORLD_SEAT_TOKEN_MAX = 512;

/**
 * The one MCP endpoint a seat may name: HTTPS on a public host, no
 * credentials, query or fragment, path exactly `/mcp`. Custody fetches it from
 * inside Fungi's own network, so a private name would be an SSRF reach.
 *
 * `allowLocalDev` is the host's explicit local/dev configuration, never
 * inferred from the URL: it additionally admits plain HTTP (or HTTPS) to a
 * loopback host so a developer's machine can serve the world.
 */
export function worldSeatEndpoint(
  text: string,
  options: Readonly<{ allowLocalDev?: boolean }> = {},
): string {
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new VeilError("invalid_input");
  }
  if (url.username || url.password || url.search || url.hash)
    throw new VeilError("invalid_input");
  if (url.pathname !== "/mcp") throw new VeilError("invalid_input");
  if (options.allowLocalDev === true && isLoopbackHost(url.hostname)) {
    if (url.protocol !== "http:" && url.protocol !== "https:")
      throw new VeilError("invalid_input");
    return url.href;
  }
  if (url.protocol !== "https:") throw new VeilError("invalid_input");
  try {
    assertPublicHostName(url.hostname);
  } catch {
    throw new VeilError("invalid_input");
  }
  return url.href;
}

function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "[::1]" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/u.test(hostname)
  );
}

const forwardedHeaders = [
  "accept",
  "content-type",
  "mcp-protocol-version",
  "mcp-session-id",
  "last-event-id",
] as const;

/** Streamable HTTP uses exactly these three verbs; any other is refused. */
const worldSeatMethods: ReadonlySet<string> = new Set([
  "GET",
  "POST",
  "DELETE",
]);

/** The seat's endpoint and nothing else; the caller names no other target. */
export function worldSeatTarget(
  access: WorldSeatAccess,
  request: Request,
): URL {
  let target: URL;
  try {
    target = new URL(request.url);
  } catch {
    throw new VeilError("denied");
  }
  if (
    target.href !== new URL(access.endpoint).href ||
    !worldSeatMethods.has(request.method)
  )
    throw new VeilError("denied");
  return target;
}

/** Copy only MCP-meaningful headers; the caller's authorization is dropped. */
export function worldSeatForwardedHeaders(request: Request): Headers {
  const headers = new Headers();
  for (const name of forwardedHeaders) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  return headers;
}
