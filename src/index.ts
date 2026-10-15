import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";

const text = Schema.NonEmptyString;
const integer = Schema.Number.check(
  Schema.isInt(),
  Schema.isGreaterThanOrEqualTo(0),
);

/** The repository identity selected by the Team, never by model input. */
export const RepositoryScopeSchema = Schema.Struct({
  id: integer.check(Schema.isGreaterThan(0)),
  owner: text,
  name: text,
});
export type RepositoryScope = Schema.Schema.Type<typeof RepositoryScopeSchema>;

/** Bounded, credential-free metadata returned by the GitHub operation. */
export const GitHubRepositorySchema = Schema.Struct({
  id: integer.check(Schema.isGreaterThan(0)),
  name: text,
  fullName: text,
  private: Schema.Boolean,
  defaultBranch: text,
});
export type GitHubRepository = Schema.Schema.Type<
  typeof GitHubRepositorySchema
>;
const providerRepositorySchema = Schema.Struct({
  id: GitHubRepositorySchema.fields.id,
  name: text,
  full_name: GitHubRepositorySchema.fields.fullName,
  private: Schema.Boolean,
  default_branch: text,
});

export const ConnectInputSchema = Schema.Struct({
  requestId: text,
  actorUserId: text,
  holderAgentId: text,
  repository: RepositoryScopeSchema,
});
export type ConnectInput = Schema.Schema.Type<typeof ConnectInputSchema>;
export const AttemptSchema = Schema.Struct({
  ...ConnectInputSchema.fields,
  teamId: text,
  attemptId: text,
  connectionId: text,
  integrationId: text,
  expiresAt: integer,
});
export type ConnectionAttempt = Schema.Schema.Type<typeof AttemptSchema>;

/** Custody correlation is independent of the resource receiving the Connection. */
export type CustodyCorrelation = Pick<
  ConnectionAttempt,
  "teamId" | "attemptId" | "actorUserId" | "integrationId"
>;

/** Produced only by a custodian's verified completion boundary. */
export const CompletionSchema = Schema.Struct({
  teamId: text,
  attemptId: text,
  principalId: text,
  integrationId: text,
  locator: text,
});
export type VerifiedCompletion = Schema.Schema.Type<typeof CompletionSchema>;

export const ConnectionReceiptSchema = Schema.Struct({
  requestId: text,
  connectionId: text,
  holderAgentId: text,
  repository: RepositoryScopeSchema,
  authorityVersion: integer,
  status: Schema.Literals(["active", "disconnected"]),
  cleanup: Schema.Literals(["none", "pending"]),
});
export type ConnectionReceipt = Schema.Schema.Type<
  typeof ConnectionReceiptSchema
>;
export const ReadBindingSchema = Schema.Struct({
  teamId: text,
  holderAgentId: text,
  connectionId: text,
  repositoryId: integer,
});
export type ReadBinding = Schema.Schema.Type<typeof ReadBindingSchema>;
export const DisconnectInputSchema = Schema.Struct({
  requestId: text,
  actorUserId: text,
  connectionId: text,
});
export type DisconnectInput = Schema.Schema.Type<typeof DisconnectInputSchema>;

/** Private to the Team owner and its trusted custodian adapter. */
export type RepositoryAccess = Readonly<{
  locator: string;
  repository: RepositoryScope;
}>;
export type PreparedCompletion =
  | Readonly<{ status: "pending"; attempt: ConnectionAttempt }>
  | Readonly<{ status: "completed"; receipt: ConnectionReceipt }>;
/** Why a verified completion's Nango connection is not held by the Team. */
export type OrphanCode =
  "expired" | "denied" | "conflict" | "reconnect_required";
/** A verified completion is held (completed), still activatable (pending), or an
 * orphan whose external connection the Team will never hold. */
export type CompletionDecision =
  PreparedCompletion | Readonly<{ status: "orphaned"; code: OrphanCode }>;
/** Terminal custodian evidence that the held credential no longer works. */
export type ReconnectReason = "refresh_failed" | "provider_unauthorized";
export type ReconnectOutcome =
  | Readonly<{ status: "reconnect_required"; connectionId: string }>
  | Readonly<{ status: "not_held" }>;
/** Signed Nango auth webhooks this Team handles; every other operation is refused. */
export type VerifiedWebhook = Readonly<{
  operation: "creation" | "refresh_failed";
  completion: VerifiedCompletion;
}>;
export type CleanupWork = Readonly<{
  connectionId: string;
  authorityVersion: number;
  locator: string;
}>;
const completionLookupSchema = Schema.Union([
  Schema.Struct({ status: Schema.Literal("unresolved") }),
  Schema.Struct({ status: Schema.Literal("ambiguous") }),
  Schema.Struct({
    status: Schema.Literal("verified"),
    completion: CompletionSchema,
  }),
]);

/** Private Team operations. Mutations may await the native SQL+wake commit. */
export type TeamConnectionsOwner = Readonly<{
  begin: (input: ConnectInput) => PreparedCompletion;
  readAttempt: (input: ConnectInput) => PreparedCompletion;
  prepareCompletion: (input: VerifiedCompletion) => CompletionDecision;
  /** Records the settled external deletion of a connection the Team never held. */
  recordOrphan: (
    input: VerifiedCompletion,
    code: OrphanCode,
    custody: "deleted" | "absent",
  ) => void;
  /** Marks the active Connection holding this locator as needing reconnection. */
  requireReconnect: (
    locator: string,
    reason: ReconnectReason,
  ) => ReconnectOutcome;
  activate: (
    input: VerifiedCompletion,
    repository: GitHubRepository,
  ) => ConnectionReceipt | Promise<ConnectionReceipt>;
  authorize: (binding: ReadBinding) => RepositoryAccess;
  disconnect: (
    input: DisconnectInput,
  ) => ConnectionReceipt | Promise<ConnectionReceipt>;
  nextCleanup: () => CleanupWork | undefined;
  acknowledgeCleanup: (work: CleanupWork) => void;
}>;

const connectSessionSchema = Schema.Struct({
  token: text,
  connectUrl: Schema.String,
  expiresAt: integer,
});

/** Ordinary Promise port. Only this trusted edge touches external custody. */
export type CredentialCustodian = Readonly<{
  openSession: (
    input: Readonly<{
      teamId: string;
      attemptId: string;
      principalId: string;
      integrationId: string;
    }>,
    signal: AbortSignal,
  ) => Promise<
    Readonly<{ token: string; connectUrl: string; expiresAt: number }>
  >;
  /** Connection creation only; refuses every other signed operation. */
  verifyCompletion: (
    rawBody: string,
    signature: string,
  ) => Promise<VerifiedCompletion>;
  verifyWebhook: (
    rawBody: string,
    signature: string,
  ) => Promise<VerifiedWebhook>;
  /** Verified means supported complete correlation, never an arbitrary list-page candidate. */
  findCompletion: (
    attempt: CustodyCorrelation,
    signal: AbortSignal,
  ) => Promise<Schema.Schema.Type<typeof completionLookupSchema>>;
  /** Only confirmed deletion or a specifically decoded missing-connection result settles cleanup. */
  deleteConnection: (
    locator: string,
    signal: AbortSignal,
  ) => Promise<"deleted" | "absent">;
  readRepository: (
    access: RepositoryAccess,
    signal: AbortSignal,
  ) => Promise<string>;
}>;

/** Sanitized public failure; an optional cause is retained internally only. */
export class VeilError extends Error {
  public constructor(
    public readonly code:
      | "denied"
      | "invalid_input"
      | "invalid_completion"
      | "invalid_response"
      | "conflict"
      | "ambiguous"
      | "expired"
      | "unavailable"
      | "github_not_configured"
      | "cancelled"
      | "reconnect_required"
      | "unsupported"
      /** GitHub refused the repository: it is outside the App installation. */
      | "repository_not_installed"
      /** The provider's rate limit refused this request; retry later. */
      | "rate_limited",
    cause?: unknown,
  ) {
    super(code);
    this.name = "VeilError";
    if (cause !== undefined)
      Object.defineProperty(this, "cause", { value: cause, enumerable: false });
  }
}

const orphanCodes: ReadonlySet<VeilError["code"]> = new Set<OrphanCode>([
  "expired",
  "denied",
  "conflict",
  "reconnect_required",
]);

function failure(cause: unknown): VeilError {
  return new VeilError(cause instanceof VeilError ? cause.code : "unavailable");
}
function owned<A>(operation: () => A): Effect.Effect<A, VeilError> {
  return Effect.try({ try: operation, catch: failure });
}
function run<A>(
  program: Effect.Effect<A, VeilError>,
  signal?: AbortSignal,
): Promise<A> {
  return Effect.runPromiseExit(
    program,
    signal === undefined ? undefined : { signal },
  ).then((exit) => {
    if (Exit.isSuccess(exit)) return exit.value;
    const error = Option.getOrUndefined(Cause.findErrorOption(exit.cause));
    throw (
      error ??
      new VeilError(
        Cause.hasInterrupts(exit.cause) ? "cancelled" : "unavailable",
      )
    );
  });
}

/** One Effect policy behind the ordinary connect and GitHub Gatekeeper calls. */
export function createGitHubConnections(
  options: Readonly<{
    owner: TeamConnectionsOwner;
    custodian: CredentialCustodian;
  }>,
) {
  const { owner, custodian } = options;
  const repository = (access: RepositoryAccess) =>
    Effect.gen(function* () {
      const raw = yield* Effect.tryPromise({
        try: (signal) => custodian.readRepository(access, signal),
        catch: failure,
      });
      const result = yield* Schema.decodeUnknownEffect(
        Schema.fromJsonString(providerRepositorySchema),
      )(raw).pipe(Effect.mapError(() => new VeilError("invalid_response")));
      if (result.id !== access.repository.id)
        return yield* Effect.fail(new VeilError("denied"));
      return {
        id: result.id,
        name: result.name,
        fullName: result.full_name,
        private: result.private,
        defaultBranch: result.default_branch,
      } satisfies GitHubRepository;
    });
  /** Delete a verified connection the Team will never hold, then refuse it. */
  const release = (completion: VerifiedCompletion, code: OrphanCode) =>
    Effect.gen(function* () {
      const raw = yield* Effect.tryPromise({
        try: (signal) => custodian.deleteConnection(completion.locator, signal),
        catch: failure,
      });
      const custody = yield* Schema.decodeUnknownEffect(
        Schema.Literals(["deleted", "absent"]),
      )(raw).pipe(Effect.mapError(() => new VeilError("invalid_response")));
      yield* owned(() => {
        owner.recordOrphan(completion, code, custody);
      });
      return yield* Effect.fail(new VeilError(code));
    });
  const activate = (verified: VerifiedCompletion) =>
    Effect.gen(function* () {
      const completion = yield* Schema.decodeUnknownEffect(CompletionSchema)(
        verified,
      ).pipe(Effect.mapError(() => new VeilError("invalid_completion")));
      const prepared = yield* owned(() => owner.prepareCompletion(completion));
      if (prepared.status === "completed") return prepared.receipt;
      if (prepared.status === "orphaned")
        return yield* release(completion, prepared.code);
      const { attempt } = prepared;
      return yield* Effect.gen(function* () {
        const metadata = yield* repository({
          locator: completion.locator,
          repository: attempt.repository,
        });
        return yield* Effect.tryPromise({
          try: async () => owner.activate(completion, metadata),
          catch: failure,
        });
      }).pipe(
        Effect.catchIf(
          (error): error is VeilError & { code: OrphanCode } =>
            orphanCodes.has(error.code),
          (error) =>
            Effect.gen(function* () {
              // A concurrent delivery of this same completion may have won.
              const settled = yield* owned(() =>
                owner.prepareCompletion(completion),
              );
              if (settled.status === "completed") return settled.receipt;
              return yield* release(completion, error.code);
            }),
        ),
      );
    });
  return {
    connect: (input: ConnectInput, signal?: AbortSignal) =>
      run(
        Effect.gen(function* () {
          const command = yield* Schema.decodeUnknownEffect(ConnectInputSchema)(
            input,
          ).pipe(Effect.mapError(() => new VeilError("invalid_input")));
          const prepared = yield* owned(() => owner.begin(command));
          if (prepared.status === "completed") return prepared;
          const { attempt } = prepared;
          const rawSession = yield* Effect.tryPromise({
            try: (control) =>
              custodian.openSession(
                {
                  teamId: attempt.teamId,
                  attemptId: attempt.attemptId,
                  principalId: attempt.actorUserId,
                  integrationId: attempt.integrationId,
                },
                control,
              ),
            catch: failure,
          });
          const session = yield* Schema.decodeUnknownEffect(
            connectSessionSchema,
          )(rawSession).pipe(
            Effect.mapError(() => new VeilError("invalid_response")),
          );
          return {
            status: "pending" as const,
            attemptId: attempt.attemptId,
            ...session,
          };
        }),
        signal,
      ),
    /** The one entry for signed custodian webhooks: activation or reconnect evidence. */
    complete: (rawBody: string, signature: string, signal?: AbortSignal) =>
      run(
        Effect.gen(function* () {
          const event = yield* Effect.tryPromise({
            try: () => custodian.verifyWebhook(rawBody, signature),
            catch: failure,
          });
          if (event.operation === "creation")
            return yield* activate(event.completion);
          const completion = yield* Schema.decodeUnknownEffect(
            CompletionSchema,
          )(event.completion).pipe(
            Effect.mapError(() => new VeilError("invalid_completion")),
          );
          const prepared = yield* owned(() =>
            owner.prepareCompletion(completion),
          );
          if (prepared.status !== "completed")
            return { status: "not_held" } satisfies ReconnectOutcome;
          return yield* owned(() =>
            owner.requireReconnect(completion.locator, "refresh_failed"),
          );
        }),
        signal,
      ),
    reconcile: (input: ConnectInput, signal?: AbortSignal) =>
      run(
        Effect.gen(function* () {
          const command = yield* Schema.decodeUnknownEffect(ConnectInputSchema)(
            input,
          ).pipe(Effect.mapError(() => new VeilError("invalid_input")));
          const prepared = yield* owned(() => owner.readAttempt(command));
          if (prepared.status === "completed") return prepared;
          const raw = yield* Effect.tryPromise({
            try: (control) =>
              custodian.findCompletion(prepared.attempt, control),
            catch: failure,
          });
          const result = yield* Schema.decodeUnknownEffect(
            completionLookupSchema,
          )(raw).pipe(Effect.mapError(() => new VeilError("invalid_response")));
          if (result.status === "ambiguous")
            return yield* Effect.fail(new VeilError("ambiguous"));
          if (result.status === "unresolved")
            return {
              status: "pending" as const,
              attemptId: prepared.attempt.attemptId,
            };
          if (result.completion.attemptId !== prepared.attempt.attemptId)
            return yield* Effect.fail(new VeilError("invalid_completion"));
          const receipt = yield* activate(result.completion);
          return { status: "completed" as const, receipt };
        }),
        signal,
      ),
    /** One bounded host recovery call; durable pending work survives interrupted or uncertain deletion. */
    cleanupOne: (signal?: AbortSignal) =>
      run(
        Effect.gen(function* () {
          const work = yield* owned(() => owner.nextCleanup());
          if (work === undefined) return { status: "idle" as const };
          const raw = yield* Effect.tryPromise({
            try: (control) => custodian.deleteConnection(work.locator, control),
            catch: failure,
          });
          const custody = yield* Schema.decodeUnknownEffect(
            Schema.Literals(["deleted", "absent"]),
          )(raw).pipe(Effect.mapError(() => new VeilError("invalid_response")));
          yield* owned(() => {
            owner.acknowledgeCleanup(work);
          });
          return {
            status: "completed" as const,
            connectionId: work.connectionId,
            authorityVersion: work.authorityVersion,
            custody,
          };
        }),
        signal,
      ),
    readRepository: (binding: ReadBinding, signal?: AbortSignal) =>
      run(
        Effect.gen(function* () {
          const command = yield* Schema.decodeUnknownEffect(ReadBindingSchema)(
            binding,
          ).pipe(Effect.mapError(() => new VeilError("invalid_input")));
          // Admission is the fresh owner decision immediately before this one egress.
          const access = yield* owned(() => owner.authorize(command));
          return yield* repository(access).pipe(
            Effect.tapError((error) =>
              error.code === "reconnect_required"
                ? owned(() =>
                    owner.requireReconnect(
                      access.locator,
                      "provider_unauthorized",
                    ),
                  ).pipe(Effect.asVoid)
                : Effect.void,
            ),
          );
        }),
        signal,
      ),
    disconnect: (input: DisconnectInput) =>
      run(
        Effect.gen(function* () {
          const command = yield* Schema.decodeUnknownEffect(
            DisconnectInputSchema,
          )(input).pipe(Effect.mapError(() => new VeilError("invalid_input")));
          return yield* Effect.tryPromise({
            try: async () => owner.disconnect(command),
            catch: failure,
          });
        }),
      ),
  };
}

export type GitHubConnections = ReturnType<typeof createGitHubConnections>;
