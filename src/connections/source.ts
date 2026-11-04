import {
  CapabilityFailed,
  Mycelium,
  type CapabilitySource,
} from "@fungi.computer/mycelium";
import { jsonSchemaToZod } from "@fungi.computer/forage";
import * as Effect from "effect/Effect";
import { z } from "zod";
import {
  ConnectionsError,
  type ConnectionProjection,
  type EgressRef,
} from "./contract.js";
import { admits, decodeTable } from "./openapi.js";

/** A table that no longer decodes is not offered; the caller is told which connection. */
async function tryDecode(table: readonly unknown[]) {
  const outcome = await Effect.runPromise(
    Effect.result(Effect.tryPromise(() => decodeTable(table))),
  );
  return outcome._tag === "Success" ? outcome.success : null;
}

/**
 * The Agent half for OpenAPI connections: one Mycelium module per granted
 * connection, its operations built from the stored table and admitted by the
 * grant. Every call is completed by the owner; nothing here holds a credential.
 * MCP connections stay with the host's Knapsack source.
 */
export function connectionsSource(input: {
  id: string;
  /** Told when a granted connection cannot be offered, with its id and nothing else. */
  onSkipped?: (connectionId: string) => void;
  read: () => Promise<ConnectionProjection>;
  subscribe: (invalidate: () => void) => () => void;
  call: (
    ref: EgressRef,
    operation: string,
    arguments_: z.core.output<ReturnType<typeof z.json>>,
  ) => Promise<z.core.output<ReturnType<typeof z.json>>>;
}): CapabilitySource {
  return {
    id: input.id,
    acquire: async ({ signal, invalidate }) => {
      signal.throwIfAborted();
      const unsubscribe = input.subscribe(invalidate);
      const release = () => {
        unsubscribe();
        return Promise.resolve();
      };
      try {
        const captured = await input.read();
        signal.throwIfAborted();
        const modules = [];
        for (const connection of captured.connections) {
          if (connection.surface.kind !== "openapi") continue;
          // The projection crossed a boundary: decode its table again and match the digest.
          const decoded = await tryDecode(connection.surface.table);
          if (decoded?.digest !== connection.surface.digest) {
            input.onSkipped?.(connection.connectionId);
            continue;
          }
          const ref = {
            connectionId: connection.connectionId,
            grantVersion: connection.grantVersion,
          };
          const connectorModule = Mycelium.module({
            id: `connector:${connection.connectionId}`,
            name: connection.name,
            description: `Third-party connector: ${connection.name}`,
            operations: Object.fromEntries(
              decoded.operations
                .filter((operation) => admits(connection.tools, operation))
                .map((operation) => [
                  operation.name,
                  Mycelium.operation({
                    replay: "unsafe",
                    access: operation.effect,
                    description: `Third-party API text: ${operation.description}\nEffect: ${operation.effect}.`,
                    input: jsonSchemaToZod(operation.input).pipe(z.json()),
                    output: z.strictObject({
                      textSource: z.literal("third_party"),
                      value: jsonSchemaToZod(operation.output).pipe(z.json()),
                    }),
                    execute: async (arguments_, context) => {
                      context.signal.throwIfAborted();
                      try {
                        return {
                          textSource: "third_party" as const,
                          value: await input.call(
                            ref,
                            operation.name,
                            z.json().parse(arguments_),
                          ),
                        };
                      } catch (cause) {
                        throw new CapabilityFailed({
                          namespace: "connectors",
                          operation: operation.name,
                          cause: {
                            kind: "OperationFailed",
                            message:
                              cause instanceof ConnectionsError
                                ? cause.code
                                : "unavailable",
                          },
                          rawCause: cause,
                        });
                      }
                    },
                  }),
                ]),
            ),
          });
          modules.push(connectorModule);
        }
        return {
          snapshot: {
            version: JSON.stringify([
              captured.revision,
              ...captured.connections.map((connection) => [
                connection.connectionId,
                connection.version,
                connection.authorityVersion,
                connection.grantVersion,
              ]),
            ]),
            modules,
          },
          release,
        };
      } catch (error) {
        await release();
        throw error;
      }
    },
  };
}
