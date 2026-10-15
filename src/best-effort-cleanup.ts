import * as Effect from "effect/Effect";

/** Report cleanup failures without exposing provider or transport details. */
export async function bestEffortCleanup(
  operation: "nango-git-response-body" | "public-fetch-socket",
  cleanup: () => Promise<void>,
): Promise<void> {
  return Effect.runPromise(
    Effect.tryPromise({ try: cleanup, catch: () => operation }).pipe(
      Effect.tapError(() =>
        Effect.logError("veil.cleanup_failed", { operation }),
      ),
      Effect.ignore,
    ),
  );
}
