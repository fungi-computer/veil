import * as Schema from "effect/Schema";
import { VeilError } from "./index.js";

const importedSchema = Schema.Struct({ connection_id: Schema.NonEmptyString });
const deletedSchema = Schema.Struct({ success: Schema.Literal(true) });
const absentSchema = Schema.Struct({
  error: Schema.Struct({ code: Schema.Literal("unknown_connection") }),
});

/** Shared Nango API-key transport policy for private credential custodians. */
export function createNangoCustodyHttp(
  options: Readonly<{
    serverUrl: string;
    apiKey: string;
  }>,
) {
  let server: URL;
  try {
    server = new URL(options.serverUrl);
  } catch {
    throw new VeilError("invalid_input");
  }
  if (
    !options.apiKey ||
    server.username ||
    server.password ||
    server.search ||
    server.hash ||
    server.pathname !== "/" ||
    !(
      server.protocol === "https:" ||
      (server.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(server.hostname))
    )
  )
    throw new VeilError("invalid_input");

  const call = async (
    path: string,
    signal: AbortSignal,
    init: RequestInit & { headers?: Headers },
  ): Promise<Response> => {
    const headers = init.headers ?? new Headers();
    headers.set("Authorization", `Bearer ${options.apiKey}`);
    try {
      signal.throwIfAborted();
      return await fetch(new URL(path, server), {
        ...init,
        headers,
        signal,
        redirect: "manual",
      });
    } catch {
      throw new VeilError(signal.aborted ? "cancelled" : "unavailable");
    }
  };

  const text = async (response: Response, signal: AbortSignal) => {
    try {
      return await response.text();
    } catch {
      throw new VeilError(signal.aborted ? "cancelled" : "unavailable");
    }
  };

  const decode = <A, I>(schema: Schema.Codec<A, I>, raw: string): A => {
    try {
      return Schema.decodeUnknownSync(Schema.fromJsonString(schema))(raw);
    } catch {
      throw new VeilError("invalid_response");
    }
  };

  return {
    async importCredential(
      input: Readonly<{
        integrationId: string;
        locator: string;
        teamId: string;
        credential: string;
      }>,
      signal: AbortSignal,
    ): Promise<void> {
      const response = await call("/connections", signal, {
        method: "POST",
        headers: new Headers({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          provider_config_key: input.integrationId,
          connection_id: input.locator,
          credentials: { type: "API_KEY", apiKey: input.credential },
          tags: { veil_team_id: input.teamId },
        }),
      });
      const raw = await text(response, signal);
      if (!response.ok) throw new VeilError("unavailable");
      const imported = decode(importedSchema, raw);
      if (imported.connection_id !== input.locator)
        throw new VeilError("invalid_response");
    },
    async removeConnection(
      locator: string,
      integrationId: string,
      signal: AbortSignal,
    ): Promise<"deleted" | "absent"> {
      const query = new URLSearchParams({ provider_config_key: integrationId });
      const response = await call(
        `/connections/${encodeURIComponent(locator)}?${query.toString()}`,
        signal,
        { method: "DELETE" },
      );
      const raw = await text(response, signal);
      if (response.status === 400) {
        decode(absentSchema, raw);
        return "absent";
      }
      if (!response.ok) throw new VeilError("unavailable");
      decode(deletedSchema, raw);
      return "deleted";
    },
    call,
  };
}
