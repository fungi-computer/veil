import { Buffer } from "node:buffer";
import { createPublicEgressPolicy } from "./public-egress-policy.js";
import * as Effect from "effect/Effect";
import { VeilError } from "./index.js";
import {
  OpenApiError,
  type OpenApiAccess,
  type OpenApiDoorOptions,
  type OpenApiCredentialAddress,
} from "./openapi-contract.js";
import { createOpenApiSecrets } from "./openapi-secrets.js";
import { createPublicHttp } from "./public-fetch.js";
import { assertPublicHostName } from "./model-key-network.js";
import { readOpenApiBody } from "./openapi-http.js";

const credentialEncodings = (credential: string) => [
  ...new Set([
    credential,
    `Bearer ${credential}`,
    JSON.stringify(credential).slice(1, -1),
    encodeURIComponent(credential),
    encodeURIComponent(credential).replace(/%[0-9A-F]{2}/gu, (part) =>
      part.toLowerCase(),
    ),
    Buffer.from(credential).toString("base64"),
    Buffer.from(credential).toString("base64url"),
  ]),
];
const encoder = new TextEncoder();
const bodyLimit = 256 * 1024;
const methods = new Set([
  "GET",
  "HEAD",
  "OPTIONS",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
]);
const forbiddenHeader = (name: string) =>
  [
    "authorization",
    "cookie",
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "accept-encoding",
    "set-cookie",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
    "expect",
    "via",
    "forwarded",
    "x-real-ip",
    "max-forwards",
    "x-http-method-override",
    "x-method-override",
    "x-http-method",
  ].includes(name.toLowerCase()) ||
  /^(proxy-|x-forwarded-|nango-|cf-)/iu.test(name);
function sanitize(cause: unknown): OpenApiError {
  if (cause instanceof OpenApiError) return cause;
  if (cause instanceof VeilError) {
    switch (cause.code) {
      case "denied":
      case "invalid_input":
      case "invalid_response":
      case "cancelled":
        return new OpenApiError(cause.code);
    }
  }
  return new OpenApiError("unavailable");
}
const io = <A>(operation: (signal: AbortSignal) => Promise<A>) =>
  Effect.tryPromise({ try: operation, catch: sanitize });
const policy = <A>(operation: () => A) =>
  Effect.try({ try: operation, catch: sanitize });
const bounded = <A>(operation: Effect.Effect<A, OpenApiError>) =>
  operation.pipe(
    Effect.timeoutOrElse({
      duration: "30 seconds",
      orElse: () => Effect.fail(new OpenApiError("timeout")),
    }),
  );

/** Public HTTPS only. The Team supplies the pinned base, not the spec at call time. */
function base(access: OpenApiAccess): URL {
  let url: URL;
  try {
    url = new URL(access.baseUrl);
  } catch {
    throw new OpenApiError("invalid_input");
  }
  if (
    !access.teamId ||
    !access.connectorId ||
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    throw new OpenApiError("invalid_input");
  try {
    assertPublicHostName(url.hostname);
  } catch {
    throw new OpenApiError("denied");
  }
  return url;
}

function target(
  access: OpenApiAccess,
  request: Request,
  declaredHeaders: readonly string[],
): URL {
  const pinned = base(access);
  const url = new URL(request.url);
  const root = pinned.pathname.replace(/\/+$/u, "");
  if (
    url.origin !== pinned.origin ||
    url.username ||
    url.password ||
    url.hash ||
    !(url.pathname === root || url.pathname.startsWith(`${root}/`)) ||
    !methods.has(request.method)
  )
    throw new OpenApiError("denied");
  // URL normalizes literal dot segments. Encoded separators/dots must not reach an upstream decoder.
  if (/%(?:2e|2f|5c|25)/iu.test(url.pathname)) throw new OpenApiError("denied");
  const allowed = new Set([
    "accept",
    "content-type",
    ...declaredHeaders.map((name) => name.toLowerCase()),
  ]);
  for (const [name] of request.headers) {
    if (
      !allowed.has(name) ||
      forbiddenHeader(name) ||
      (access.auth.kind === "api_key_header" &&
        name.toLowerCase() === access.auth.param.toLowerCase())
    )
      throw new OpenApiError("denied");
  }
  if (
    access.auth.kind === "api_key_query" &&
    url.searchParams.has(access.auth.param)
  )
    throw new OpenApiError("denied");
  return url;
}

function credentialPolicy(access: OpenApiAccess, credential?: string) {
  base(access);
  if (access.auth.kind === "oauth") {
    if (credential !== undefined) throw new OpenApiError("invalid_input");
    return;
  }
  if (access.auth.kind === "none") {
    if (credential !== undefined) throw new OpenApiError("invalid_input");
    return;
  }
  if (
    access.auth.kind === "api_key_header" ||
    access.auth.kind === "api_key_query"
  ) {
    if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$/u.test(access.auth.param))
      throw new OpenApiError("invalid_input");
    if (
      access.auth.kind === "api_key_header" &&
      forbiddenHeader(access.auth.param)
    )
      throw new OpenApiError("invalid_input");
  }
  if (credential !== undefined) {
    if (
      credential.length === 0 ||
      encoder.encode(credential).byteLength > 16 * 1024 ||
      /[\r\n\0]/u.test(credential)
    )
      throw new OpenApiError("invalid_input");
    if (access.auth.kind !== "api_key_query") {
      try {
        new Headers({ authorization: credential });
      } catch {
        throw new OpenApiError("invalid_input");
      }
    }
  }
}

/** Canonical Effect policy; Promises appear only at socket, crypto and storage adapters. */
export type OpenApiEffects = Readonly<{
  seal: (
    access: OpenApiAccess,
    credential: string,
  ) => Effect.Effect<void, OpenApiError>;
  remove: (
    address: OpenApiCredentialAddress,
  ) => Effect.Effect<"deleted" | "absent", OpenApiError>;
  send: (
    access: OpenApiAccess,
    request: Request,
    declaredHeaders?: readonly string[],
  ) => Effect.Effect<Response, OpenApiError>;
}>;
export function createOpenApiEffects(
  options: OpenApiDoorOptions,
): OpenApiEffects {
  const http = createPublicHttp(options);
  const networkPolicy = createPublicEgressPolicy(options.networkPolicy);
  const secrets =
    options.custody === undefined
      ? undefined
      : createOpenApiSecrets(options.custody.keys);
  const store = options.custody?.store;
  return {
    seal: (access: OpenApiAccess, credential: string) =>
      bounded(
        Effect.gen(function* () {
          yield* policy(() => {
            credentialPolicy(access, credential);
            networkPolicy.destination(base(access));
          });
          if (!secrets || !store)
            return yield* Effect.fail(new OpenApiError("unavailable"));
          const sealed = yield* io(() => secrets.seal(access, credential));
          yield* io((signal) => store.write(access, sealed, signal));
        }),
      ),
    remove: (address: OpenApiCredentialAddress) =>
      bounded(
        io((signal) => {
          if (!store) throw new OpenApiError("unavailable");
          return store.remove(address, signal);
        }),
      ),
    send: (
      access: OpenApiAccess,
      request: Request,
      declaredHeaders: readonly string[] = [],
    ) =>
      bounded(
        Effect.gen(function* () {
          const url = yield* policy(() =>
            target(access, request, declaredHeaders),
          );
          yield* policy(() => {
            credentialPolicy(access);
            networkPolicy.destination(url);
          });
          const oauth =
            access.auth.kind === "oauth" &&
            options.oauthProviders !== undefined &&
            Object.hasOwn(options.oauthProviders, access.auth.provider)
              ? options.oauthProviders[access.auth.provider]
              : undefined;
          if (access.auth.kind === "oauth") {
            if (!oauth)
              return yield* Effect.fail(
                new OpenApiError("oauth_not_configured"),
              );
            // Known provider host/path only. A spec cannot redirect OAuth custody to its server.
            if (oauth.baseUrl !== access.baseUrl || !access.auth.locator)
              return yield* Effect.fail(new OpenApiError("denied"));
          }
          const body = yield* io((signal) =>
            readOpenApiBody(request.body, bodyLimit, signal),
          );
          let credential: string | undefined;
          if (access.auth.kind !== "none" && access.auth.kind !== "oauth") {
            if (!secrets || !store)
              return yield* Effect.fail(new OpenApiError("unavailable"));
            const sealed = yield* io((signal) => store.read(access, signal));
            if (sealed === null)
              return yield* Effect.fail(
                new OpenApiError("credentials_missing"),
              );
            credential = yield* io(() => secrets.open(access, sealed));
          }
          return yield* io(async (signal) => {
            const headers = new Headers(request.headers);
            if (credential !== undefined) {
              switch (access.auth.kind) {
                case "bearer":
                  headers.set("authorization", `Bearer ${credential}`);
                  break;
                case "api_key_header":
                  headers.set(access.auth.param, credential);
                  break;
                case "api_key_query":
                  url.searchParams.set(access.auth.param, credential);
                  break;
              }
            }
            let response: Response;
            if (access.auth.kind === "oauth" && oauth) {
              const init: RequestInit = {
                method: request.method,
                headers,
                signal,
                redirect: "manual",
              };
              if (!["GET", "HEAD"].includes(request.method)) init.body = body;
              response = await oauth.send(
                access.teamId,
                access.auth.locator,
                new Request(url, init),
              );
            } else {
              response = await http.send({
                url,
                method: request.method,
                headers,
                body,
                signal,
              });
            }
            const bytes = await readOpenApiBody(
              response.body,
              bodyLimit,
              signal,
            );
            // An untrusted server must not turn any common credential encoding into a model result.
            const safeBody =
              credential === undefined
                ? bytes
                : encoder.encode(
                    credentialEncodings(credential)
                      .sort((a, b) => b.length - a.length)
                      .reduce(
                        (body, value) => body.replaceAll(value, "[REDACTED]"),
                        new TextDecoder().decode(bytes),
                      ),
                  );
            if (safeBody.byteLength > bodyLimit)
              throw new OpenApiError("too_large");
            if (!response.ok)
              throw new OpenApiError("upstream_status", response.status);
            const contentType =
              (response.headers.get("content-type") ?? "")
                .split(";")[0]
                ?.trim()
                .toLowerCase() ?? "";
            if (
              credential !== undefined &&
              credentialEncodings(credential).some((value) =>
                contentType.includes(value.toLowerCase()),
              )
            )
              throw new OpenApiError("invalid_response");
            if (
              bytes.byteLength > 0 &&
              !/^(application\/(?:[a-z0-9.+-]+\+)?json|text\/[a-z0-9.+-]+)(?:\s*;|$)/iu.test(
                contentType,
              )
            )
              throw new OpenApiError("invalid_response");
            return new Response(
              [204, 205, 304].includes(response.status) ||
                request.method === "HEAD"
                ? null
                : safeBody,
              {
                status: response.status,
                headers:
                  contentType === "" ? {} : { "content-type": contentType },
              },
            );
          });
        }),
      ),
  };
}
