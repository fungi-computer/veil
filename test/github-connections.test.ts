import { expect, it, vi } from "vitest";

import {
  createGitHubConnections,
  VeilError,
  type CredentialCustodian,
  type TeamConnectionsOwner,
} from "../src/index.js";

const repository = { id: 42, owner: "botanical", name: "bound" };
const binding = {
  teamId: "team-a",
  holderAgentId: "agent-a",
  connectionId: "connection-a",
  repositoryId: 42,
};
const providerResult = {
  id: 42,
  name: "bound",
  full_name: "botanical/bound",
  private: true,
  default_branch: "main",
};

function reader(readRepository: CredentialCustodian["readRepository"]) {
  const unused = () => {
    throw new Error("Unexpected lifecycle operation");
  };
  const authorize = vi.fn(() => ({ locator: "private-locator", repository }));
  const owner: TeamConnectionsOwner = {
    begin: unused,
    readAttempt: unused,
    prepareCompletion: unused,
    recordOrphan: unused,
    requireReconnect: unused,
    activate: unused,
    authorize,
    disconnect: unused,
    nextCleanup: unused,
    acknowledgeCleanup: unused,
  };
  const custodian: CredentialCustodian = {
    openSession: unused,
    verifyCompletion: unused,
    verifyWebhook: unused,
    findCompletion: unused,
    deleteConnection: unused,
    readRepository,
  };
  return {
    connections: createGitHubConnections({ owner, custodian }),
    authorize,
  };
}

it("preserves typed failures without exposing adapter error details", async () => {
  const privateError = new VeilError("denied");
  privateError.message = "provider-private-body";
  privateError.cause = new Error("provider-private-cause");
  const { connections } = reader(() => Promise.reject(privateError));
  const result = connections.readRepository(binding);
  await expect(result).rejects.toMatchObject({
    code: "denied",
    message: "denied",
  });
  await expect(result).rejects.not.toBe(privateError);
  await expect(result).rejects.not.toHaveProperty("cause");
});

it.each([
  ["malformed JSON", "{", "invalid_response"],
  ["wrong repository", JSON.stringify({ ...providerResult, id: 43 }), "denied"],
])(
  "rejects %s instead of returning provider data",
  async (_name, body, code) => {
    const { connections } = reader(() => Promise.resolve(body));
    await expect(connections.readRepository(binding)).rejects.toMatchObject({
      code,
    });
  },
);

it("returns only repository metadata and makes a fresh decision for every read", async () => {
  const { connections, authorize } = reader(() =>
    Promise.resolve(
      JSON.stringify({ ...providerResult, extra: "private-provider-data" }),
    ),
  );
  for (let read = 0; read < 2; read += 1) {
    await expect(connections.readRepository(binding)).resolves.toEqual({
      id: 42,
      name: "bound",
      fullName: "botanical/bound",
      private: true,
      defaultBranch: "main",
    });
  }
  expect(authorize).toHaveBeenCalledTimes(2);
  expect(authorize).toHaveBeenCalledWith(binding);
});

it("propagates cancellation to custody and permits a subsequent authorized read", async () => {
  const admitted = Promise.withResolvers<AbortSignal>();
  const remote = Promise.withResolvers<string>();
  const { connections, authorize } = reader((_access, signal) => {
    admitted.resolve(signal);
    return remote.promise;
  });
  const controller = new AbortController();
  const pending = connections.readRepository(binding, controller.signal);
  const rejection = expect(pending).rejects.toMatchObject({
    code: "cancelled",
  });
  const custodySignal = await admitted.promise;
  controller.abort();
  await rejection;
  expect(custodySignal.aborted).toBe(true);
  // Transport cancellation cannot roll back a provider operation already admitted.
  remote.resolve(JSON.stringify(providerResult));
  await expect(connections.readRepository(binding)).resolves.toMatchObject({
    id: 42,
  });
  expect(authorize).toHaveBeenCalledTimes(2);
});

it.each(["activate", "disconnect"] as const)(
  "awaits %s commit and preserves a failed durable wake as unavailable",
  async (operation) => {
    let failCommit: (error: Error) => void = () => {
      throw new Error("Commit not entered");
    };
    let entered: () => void = () => undefined;
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const commit = () =>
      new Promise<never>((_resolve, reject) => {
        failCommit = reject;
        entered();
      });
    const unused = () => {
      throw new Error("Unexpected owner call");
    };
    const attempt = {
      requestId: "connect",
      actorUserId: "member",
      holderAgentId: binding.holderAgentId,
      repository,
      teamId: binding.teamId,
      attemptId: "attempt",
      connectionId: binding.connectionId,
      integrationId: "github",
      expiresAt: 2000000000000,
    };
    const owner: TeamConnectionsOwner = {
      begin: unused,
      readAttempt: unused,
      prepareCompletion: () => ({ status: "pending", attempt }),
      recordOrphan: unused,
      requireReconnect: unused,
      activate: commit,
      disconnect: commit,
      authorize: unused,
      nextCleanup: unused,
      acknowledgeCleanup: unused,
    };
    const custodian: CredentialCustodian = {
      openSession: unused,
      findCompletion: unused,
      deleteConnection: unused,
      verifyCompletion: unused,
      verifyWebhook: () =>
        Promise.resolve({
          operation: "creation",
          completion: {
            teamId: binding.teamId,
            attemptId: attempt.attemptId,
            principalId: attempt.actorUserId,
            integrationId: attempt.integrationId,
            locator: "private-locator",
          },
        }),
      readRepository: () => Promise.resolve(JSON.stringify(providerResult)),
    };
    const caller = createGitHubConnections({ owner, custodian });
    const result =
      operation === "activate"
        ? caller.complete("verified fixture", "fixture signature")
        : caller.disconnect({
            requestId: "disconnect",
            actorUserId: "member",
            connectionId: binding.connectionId,
          });
    let settled = false;
    void result.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    const rejected = expect(result).rejects.toMatchObject({
      code: "unavailable",
      message: "unavailable",
    });
    await started;
    expect(settled).toBe(false);
    failCommit(new Error("private native alarm detail"));
    await rejected;
  },
);
