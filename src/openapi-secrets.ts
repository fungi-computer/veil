import {
  OpenApiError,
  type OpenApiCredentialKeyring,
  type OpenApiAccess,
} from "./openapi-contract.js";
import { createCredentialSealer } from "./credential-store.js";

/** The connector's owner address and policy are the sealed value's context. */
const context = (access: OpenApiAccess) => [
  access.teamId,
  access.connectorId,
  access.baseUrl,
  access.auth.kind,
  access.auth.kind === "api_key_header" || access.auth.kind === "api_key_query"
    ? access.auth.param
    : null,
];

/** Connector credentials sealed by Veil's one credential sealer. */
export function createOpenApiSecrets(configuration: OpenApiCredentialKeyring) {
  const sealer = (() => {
    try {
      return createCredentialSealer(configuration, "fungi.veil.openapi.v1");
    } catch {
      throw new OpenApiError("unavailable");
    }
  })();
  return {
    async seal(access: OpenApiAccess, credential: string): Promise<string> {
      try {
        return await sealer.seal(context(access), credential);
      } catch {
        throw new OpenApiError("denied");
      }
    },
    async open(access: OpenApiAccess, sealed: string): Promise<string> {
      try {
        return await sealer.open(context(access), sealed);
      } catch {
        throw new OpenApiError("denied");
      }
    },
  };
}
