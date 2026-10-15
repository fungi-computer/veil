import { VeilError } from "./index.js";
import { createNangoCustodyHttp } from "./nango-custody-http.js";
import {
  WORLD_SEAT_TOKEN_MAX,
  worldSeatEndpoint,
  worldSeatForwardedHeaders,
  worldSeatTarget,
  type WorldSeatCustodian,
} from "./world-seat.js";

/**
 * Trusted host configuration: one Nango bearer-token integration whose proxy
 * attaches the sealed token to the seat's own endpoint.
 */
export type NangoWorldSeatOptions = Readonly<{
  serverUrl: string;
  apiKey: string;
  integrationId: string;
  /** The host's explicit local/dev flag: admits a loopback seat endpoint. */
  allowLocalDev?: boolean;
}>;

/** Nango custody for world-seat tokens: import once, proxy at egress, delete. */
export function createNangoWorldSeatCustodian(
  options: NangoWorldSeatOptions,
): WorldSeatCustodian {
  if (!options.integrationId) throw new VeilError("invalid_input");
  const http = createNangoCustodyHttp(options);

  return {
    async seal(input, signal) {
      worldSeatEndpoint(input.endpoint, {
        allowLocalDev: options.allowLocalDev === true,
      });
      if (input.token.length === 0 || input.token.length > WORLD_SEAT_TOKEN_MAX)
        throw new VeilError("invalid_input");
      await http.importCredential(
        {
          integrationId: options.integrationId,
          locator: input.locator,
          teamId: input.teamId,
          credential: input.token,
        },
        signal,
      );
    },
    async send(access, request) {
      const target = worldSeatTarget(access, request);
      const headers = new Headers();
      for (const [name, value] of worldSeatForwardedHeaders(request))
        headers.set(`Nango-Proxy-${name}`, value);
      const contentType = request.headers.get("content-type");
      if (contentType !== null) headers.set("Content-Type", contentType);
      headers.set("Provider-Config-Key", options.integrationId);
      headers.set("Connection-Id", access.locator);
      headers.set("Base-Url-Override", target.origin);
      headers.set("Retries", "0");
      return await http.call(`/proxy${target.pathname}`, request.signal, {
        method: request.method,
        headers,
        body: request.method === "POST" ? request.body : null,
        // Native Node fetch requires this for a stream; Workers accepts it.
        duplex: "half",
      });
    },
    async remove(access, signal) {
      return http.removeConnection(
        access.locator,
        options.integrationId,
        signal,
      );
    },
  };
}
