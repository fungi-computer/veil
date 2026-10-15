import { VeilError } from "./index.js";
import { createNangoCustodyHttp } from "./nango-custody-http.js";
import {
  modelKeyForwardedHeaders,
  modelKeyTarget,
  type ModelKeyCustodian,
  type ModelKeyProvider,
} from "./model-keys.js";

/**
 * Trusted host configuration. Each provider maps to a Nango API-key
 * integration whose proxy attaches that provider's auth header.
 * `openai-compatible` uses a bearer-token integration with a base override.
 */
export type NangoModelKeyOptions = Readonly<{
  serverUrl: string;
  apiKey: string;
  integrations: Readonly<Partial<Record<ModelKeyProvider, string>>>;
}>;

/** Nango custody for Team model API keys: import once, proxy at egress, delete. */
export function createNangoModelKeyCustodian(
  options: NangoModelKeyOptions,
): ModelKeyCustodian {
  const http = createNangoCustodyHttp(options);
  const integration = (provider: ModelKeyProvider): string => {
    const id = options.integrations[provider];
    if (id === undefined || id.length === 0) throw new VeilError("unavailable");
    return id;
  };
  return {
    async seal(input, signal) {
      if (input.apiKey.length === 0 || input.apiKey.length > 16_384)
        throw new VeilError("invalid_input");
      await http.importCredential(
        {
          integrationId: integration(input.provider),
          locator: input.locator,
          teamId: input.teamId,
          credential: input.apiKey,
        },
        signal,
      );
    },
    async send(access, request) {
      const target = modelKeyTarget(access, request);
      const headers = new Headers();
      for (const [name, value] of modelKeyForwardedHeaders(request))
        headers.set(`Nango-Proxy-${name}`, value);
      const contentType = request.headers.get("content-type");
      if (contentType !== null) headers.set("Content-Type", contentType);
      headers.set("Provider-Config-Key", integration(access.provider));
      headers.set("Connection-Id", access.locator);
      headers.set("Base-Url-Override", target.origin);
      headers.set("Retries", "0");
      return await http.call(
        `/proxy${target.pathname}${target.search}`,
        request.signal,
        {
          method: request.method,
          headers,
          body: request.method === "GET" ? null : request.body,
          // Native Node fetch requires this for a stream; Workers accepts it.
          duplex: "half",
        },
      );
    },
    async remove(access, signal) {
      return http.removeConnection(
        access.locator,
        integration(access.provider),
        signal,
      );
    },
  };
}
