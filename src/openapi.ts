import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Cause from "effect/Cause";
import * as Option from "effect/Option";
import {
  OpenApiError,
  type OpenApiDoor,
  type OpenApiDoorOptions,
} from "./openapi-contract.js";
import { createOpenApiEffects } from "./openapi-effect.js";
export { OpenApiError };
export type { PublicEgressPolicy } from "./public-egress-policy.js";
export type {
  OpenApiAccess,
  OpenApiAuth,
  OpenApiCredentialAddress,
  OpenApiCredentialKeyring,
  OpenApiCredentialStore,
  OpenApiDoor,
  OpenApiDoorOptions,
  OpenApiOAuthProvider,
  OpenApiRefusal,
} from "./openapi-contract.js";

/** The one Promise facade; cancellation interrupts the same Effect-owned operation. */
function run<A>(
  effect: Effect.Effect<A, OpenApiError>,
  signal: AbortSignal,
): Promise<A> {
  return Effect.runPromiseExit(effect, { signal }).then((exit) => {
    if (Exit.isSuccess(exit)) return exit.value;
    throw (
      Option.getOrUndefined(Cause.findErrorOption(exit.cause)) ??
      new OpenApiError(
        Cause.hasInterrupts(exit.cause) ? "cancelled" : "unavailable",
      )
    );
  });
}

export function createOpenApiDoor(options: OpenApiDoorOptions): OpenApiDoor {
  const effects = createOpenApiEffects(options);
  return {
    seal: (access, credential, signal) =>
      run(effects.seal(access, credential), signal),
    send: (access, request, declaredHeaders) =>
      run(effects.send(access, request, declaredHeaders), request.signal),
    remove: (address, signal) => run(effects.remove(address), signal),
  };
}
