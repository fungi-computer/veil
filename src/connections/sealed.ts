import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import { oauthBundleJson } from "./oauth.js";
import {
  ConnectionsError,
  type Credential,
  type CustodyAdapter,
  type Placement,
} from "./contract.js";

/**
 * The slice of Veil's one credential store (`createCredentialStore`) that sealed
 * custody needs: ciphertext at rest, the secret released only into a callback.
 */
export type CredentialVault = Readonly<{
  put: (input: {
    kind: string;
    label: string;
    secret: string;
  }) => Promise<{ credentialId: string }>;
  withSecret: <T>(
    credentialId: string,
    action: (secret: string) => Promise<T> | T,
  ) => Promise<T>;
  remove: (credentialId: string) => Promise<"deleted" | "absent">;
}>;

/** Where a static secret rides on the final request. */
function applyPlacement(
  request: Request,
  placement: Placement,
  secret: string,
): Request {
  if (placement !== "bearer" && "query" in placement) {
    const target = new URL(request.url);
    target.searchParams.set(placement.query, secret);
    return new Request(target.href, request);
  }
  const headers = new Headers(request.headers);
  if (placement === "bearer") headers.set("authorization", `Bearer ${secret}`);
  else headers.set(placement.header, secret);
  return new Request(request, { headers });
}

const failure = Schema.decodeUnknownSync(
  Schema.Struct({ code: Schema.String }),
);
const refusal = (cause: unknown) => {
  if (cause instanceof ConnectionsError) return cause;
  try {
    const { code } = failure(cause);
    return new ConnectionsError(
      code === "absent" || code === "denied"
        ? "reconnect_required"
        : "unavailable",
      { cause },
    );
  } catch {
    return new ConnectionsError("unavailable", { cause });
  }
};

/** Attach the sealed secret the way the credential says. */
function authorized(
  credential: Credential,
  secret: string,
  request: Request,
): Request {
  if (credential.kind === "static")
    return applyPlacement(request, credential.placement, secret);
  if (credential.kind === "none") return request;
  const bundle = Schema.decodeUnknownOption(oauthBundleJson)(secret);
  if (bundle._tag === "None" || bundle.value.tokens === undefined)
    throw new ConnectionsError("reconnect_required");
  return applyPlacement(request, "bearer", bundle.value.tokens.access_token);
}

/** Default custody: a thin adapter over the shared credential store. `send` is the checked public transport. */
export function createSealedCustody(options: {
  vault: CredentialVault;
  send: (request: Request) => Promise<Response>;
}): CustodyAdapter {
  return {
    put: (address, secret) =>
      Effect.tryPromise({
        try: async () =>
          (
            await options.vault.put({
              kind: "connection",
              label: address.connectionId,
              secret,
            })
          ).credentialId,
        catch: refusal,
      }),
    inject: (address, locator, request) =>
      address.credential.kind === "none"
        ? Effect.tryPromise({
            try: () => options.send(request),
            catch: refusal,
          })
        : Effect.tryPromise({
            try: () =>
              options.vault.withSecret(locator, (secret) =>
                options.send(authorized(address.credential, secret, request)),
              ),
            catch: refusal,
          }),
    open: (_address, locator) =>
      Effect.tryPromise({
        try: () => options.vault.withSecret(locator, (secret) => secret),
        catch: refusal,
      }),
    remove: (_address, locator) =>
      Effect.tryPromise({
        try: () => options.vault.remove(locator),
        catch: refusal,
      }),
  };
}
