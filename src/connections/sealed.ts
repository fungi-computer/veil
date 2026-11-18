import { Buffer } from "node:buffer";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import { createKnownValueRedactor } from "../redaction.js";
import { oauthBundleJson } from "./oauth.js";
import {
  ConnectionsError,
  type Credential,
  type CustodyAdapter,
  type CustodyObserver,
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
  const headers = new Headers(request.headers);
  if (placement === "bearer") headers.set("authorization", `Bearer ${secret}`);
  else if (placement === "basic")
    headers.set("authorization", `Basic ${btoa(secret)}`);
  else if ("query" in placement) {
    const target = new URL(request.url);
    target.searchParams.set(placement.query, secret);
    return new Request(target.href, request);
  } else headers.set(placement.header, secret);
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

/** Body framing that the redacted body no longer matches. */
const bodyFraming = new Set(["content-length", "content-encoding"]);

/**
 * The upstream response with every echo of `secret` masked: in each encoding
 * Veil's redactor registers, in headers (dropped) and across body chunks. The
 * body is read as Latin-1, one code unit per byte, so the bytes around a
 * masked value pass through unchanged. If the redactor cannot settle, the
 * body errors rather than flush raw bytes.
 */
async function echoChecked(
  response: Response,
  secret: string,
  observer: CustodyObserver | undefined,
): Promise<Response> {
  const redactor = createKnownValueRedactor([secret]);
  let reported = false;
  const report = () => {
    if (reported) return;
    reported = true;
    observer?.echoed();
  };
  const headers = new Headers();
  for (const [name, value] of response.headers) {
    if (bodyFraming.has(name)) continue;
    if (await redactor.contains(value)) report();
    else headers.append(name, value);
  }
  if (response.body === null)
    return new Response(null, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  const stream = redactor.stream();
  const settle = (result: Awaited<ReturnType<typeof stream.write>>) => {
    if (result.status === "unavailable")
      throw new ConnectionsError("unavailable");
    if (result.status === "redacted") report();
    return Buffer.from(result.text, "latin1");
  };
  const body = response.body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      async transform(chunk, controller) {
        const settled = settle(
          await stream.write(Buffer.from(chunk).toString("latin1")),
        );
        if (settled.byteLength > 0) controller.enqueue(settled);
      },
      async flush(controller) {
        const settled = settle(await stream.finish());
        if (settled.byteLength > 0) controller.enqueue(settled);
      },
    }),
  );
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
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
    inject: (address, locator, request, observer) =>
      address.credential.kind === "none"
        ? Effect.tryPromise({
            try: () => options.send(request),
            catch: refusal,
          })
        : Effect.tryPromise({
            try: () =>
              options.vault.withSecret(locator, async (secret) => {
                const response = await options.send(
                  authorized(address.credential, secret, request),
                );
                // A static secret is the value a bound host could echo back.
                return address.credential.kind === "static"
                  ? await echoChecked(response, secret, observer)
                  : response;
              }),
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
