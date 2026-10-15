import type { HostResolver } from "./model-key-network.js";
import type { PublicEgressPolicy } from "./public-egress-policy.js";
import type { PublicConnect } from "./public-fetch.js";

/** Only the trusted Team owner supplies access and selects a stored operation. */
export type OpenApiAuth =
  | Readonly<{ kind: "none" }>
  | Readonly<{ kind: "api_key_header" | "api_key_query"; param: string }>
  | Readonly<{ kind: "bearer" }>
  | Readonly<{ kind: "oauth"; provider: string; locator: string }>;
export type OpenApiAccess = Readonly<{
  teamId: string;
  connectorId: string;
  baseUrl: string;
  auth: OpenApiAuth;
}>;
export type OpenApiCredentialAddress = Readonly<{
  teamId: string;
  connectorId: string;
}>;

/** The host persists ciphertext only. Never give this port to an Agent or browser. */
export type OpenApiCredentialStore = Readonly<{
  read: (
    address: OpenApiCredentialAddress,
    signal: AbortSignal,
  ) => Promise<string | null>;
  write: (
    address: OpenApiCredentialAddress,
    sealed: string,
    signal: AbortSignal,
  ) => Promise<void>;
  remove: (
    address: OpenApiCredentialAddress,
    signal: AbortSignal,
  ) => Promise<"deleted" | "absent">;
}>;
/** Host-configured OAuth only: its provider fixes the upstream base and owns Nango proxying. */
export type OpenApiOAuthProvider = Readonly<{
  baseUrl: string;
  send: (
    teamId: string,
    locator: string,
    request: Request,
  ) => Promise<Response>;
}>;
export type OpenApiCredentialKeyring = Readonly<{
  activeKeyId: string;
  keys: Readonly<Record<string, string>>;
}>;
export type OpenApiDoorOptions = Readonly<{
  connect: PublicConnect;
  resolve: HostResolver;
  networkPolicy?: PublicEgressPolicy;
  /** Dedicated 32-byte base64url keys; active key seals, retained keys open. */
  custody?: Readonly<{
    keys: OpenApiCredentialKeyring;
    store: OpenApiCredentialStore;
  }>;
  oauthProviders?: Readonly<Record<string, OpenApiOAuthProvider>>;
}>;
export type OpenApiRefusal =
  | "denied"
  | "invalid_input"
  | "invalid_response"
  | "too_large"
  | "timeout"
  | "cancelled"
  | "unavailable"
  | "credentials_missing"
  | "oauth_not_configured"
  | "upstream_status";

/** Fixed codes only: upstream bodies, URLs and credential bytes never enter errors. */
export class OpenApiError extends Error {
  public constructor(
    public readonly code: OpenApiRefusal,
    public readonly status?: number,
  ) {
    super(code);
    this.name = "OpenApiError";
  }
}
export type OpenApiDoor = Readonly<{
  seal: (
    access: OpenApiAccess,
    credential: string,
    signal: AbortSignal,
  ) => Promise<void>;
  send: (
    access: OpenApiAccess,
    request: Request,
    declaredHeaders?: readonly string[],
  ) => Promise<Response>;
  remove: (
    address: OpenApiCredentialAddress,
    signal: AbortSignal,
  ) => Promise<"deleted" | "absent">;
}>;
