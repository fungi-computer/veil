import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import { assertPublicHostName } from "../model-key-network.js";
import type { createPublicEgressPolicy } from "../public-egress-policy.js";
import {
  ConnectionsError,
  identifier,
  type CompleteInput,
  type CustodyCompletion,
  type ConnectionDraft,
  type ConnectionsOptions,
  type CustodyAddress,
} from "./contract.js";
import {
  decode,
  io,
  sync,
  type AttemptRow,
  type ConnectionRow,
} from "./internal.js";
import {
  finishStaticAuthorization,
  refreshStaticTokens,
  startStaticAuthorization,
} from "./oauth-provider.js";
import {
  finishAuthorization,
  oauthBundleJson,
  oauthClientJson,
  refreshTokens,
  startAuthorization,
  tokenExpired,
  type ClientRegistry,
} from "./oauth.js";

/**
 * The narrow, transactional slice of the owner's SQLite the OAuth flow needs.
 * Every method is one synchronous owner transaction; the flow never sees SQL.
 */
export type OAuthStore = Readonly<{
  connection: (id: string) => ConnectionRow;
  /** A pending connection, its attempt and the begin receipt, or nothing. */
  recordPending: (input: {
    actor: string;
    connection: ConnectionRow;
    state: string;
    /** The sealed PKCE verifier; none when the custodian runs the authorization. */
    attemptLocator: string | null;
    issuer: string;
    requestId: string;
    fingerprint: string;
    authorizeUrl: string;
  }) => void;
  /** Consume a live attempt for its actor, or retire it when expired. */
  claim: (
    actor: string,
    input: CompleteInput,
  ) => {
    attempt: AttemptRow;
    wanted: CompleteInput;
    expired: boolean;
  };
  /** Consume a live attempt the custodian runs; expired ones retire. */
  claimCustody: (state: string) => { attempt: AttemptRow; expired: boolean };
  /** The attempt failed: withdraw the pending connection and clean its verifier. */
  fail: (attempt: AttemptRow) => void;
  /** Pending becomes active with its token locator; false when it is no longer pending. */
  activate: (
    row: ConnectionRow,
    attempt: AttemptRow,
    locator: string,
  ) => boolean;
  /** Queue a sealed locator for deletion. */
  discard: (
    connectionId: string,
    locator: string,
    credential: ConnectionRow["credential"],
  ) => void;
  /** Replace the live locator after a refresh, or report why it cannot. */
  swap: (
    row: ConnectionRow,
    held: string,
    locator: string,
  ) => "applied" | ConnectionRow["state"];
  clientLocator: (issuer: string) => string | undefined;
  saveClientLocator: (issuer: string, locator: string) => void;
}>;

/** Discovery, sign-in, token refresh and the registered-client record for OAuth connections. */
export function createOAuthFlow(deps: {
  ownerId: string;
  custody: ConnectionsOptions["custody"];
  oauth: ConnectionsOptions["oauth"];
  clock: () => number;
  ids: () => string;
  policy: ReturnType<typeof createPublicEgressPolicy>;
  store: OAuthStore;
  sweep: () => Effect.Effect<void, ConnectionsError>;
}) {
  const { ownerId, custody, store } = deps;
  const address = (row: ConnectionRow): CustodyAddress => ({
    ownerId,
    connectionId: row.id,
    credential: row.credential,
  });
  const oauthPorts = () => {
    const ports = deps.oauth;
    const open = custody.open;
    if (ports === undefined || open === undefined)
      throw new ConnectionsError("unsupported");
    return { ...ports, open };
  };
  /** Every discovery, registration and token request meets the same destination rules. */
  const guardedFetch = async (
    url: string | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const ports = oauthPorts();
    const request = new Request(url, { ...init, redirect: "error" });
    const target = new URL(request.url);
    if (target.protocol !== "https:" || target.username || target.password)
      throw new ConnectionsError("denied");
    try {
      assertPublicHostName(target.hostname);
      deps.policy.destination(target);
    } catch (cause) {
      throw new ConnectionsError("denied", { cause });
    }
    return ports.fetch(request);
  };
  /** The operator's registered provider by id; a bundle naming one this host no longer holds cannot be used. */
  const staticProvider = (id: string | undefined) => {
    if (id === undefined) return undefined;
    const found = deps.oauth?.providers?.[id];
    if (found === undefined) throw new ConnectionsError("reconnect_required");
    return found;
  };
  const clientAddress = (): CustodyAddress => ({
    ownerId,
    connectionId: "oauth-clients",
    credential: { kind: "oauth" },
  });
  /** One registered client per authorization server, sealed in custody. */
  const registry: ClientRegistry = {
    lookup: (issuer) =>
      Effect.runPromise(
        Effect.gen(function* () {
          const found = yield* sync(() => store.clientLocator(issuer));
          if (found === undefined) return undefined;
          const raw = yield* sync(oauthPorts).pipe(
            Effect.flatMap((ports) => ports.open(clientAddress(), found)),
          );
          return yield* sync(() => decode(oauthClientJson, raw));
        }),
      ),
    save: (issuer, client) =>
      Effect.runPromise(
        Effect.gen(function* () {
          const locator = yield* custody.put(
            clientAddress(),
            Schema.encodeSync(oauthClientJson)(client),
          );
          yield* sync(() => {
            store.saveClientLocator(issuer, locator);
          });
        }),
      ),
  };
  const readBundle = (row: ConnectionRow, locator: string) =>
    sync(oauthPorts).pipe(
      Effect.flatMap((ports) => ports.open(address(row), locator)),
      Effect.flatMap((raw) =>
        Effect.try({
          try: () => Schema.decodeUnknownSync(oauthBundleJson)(raw),
          catch: (cause) =>
            new ConnectionsError("reconnect_required", { cause }),
        }),
      ),
    );

  /** The custodian runs the authorization: we hold only the page to send the owner to. */
  const beginCustody = (
    actor: string,
    draft: ConnectionDraft,
    credential: Extract<ConnectionDraft["credential"], { kind: "oauth" }>,
    endpoint: string,
    fingerprint: string,
    openapi: Readonly<{ table: readonly unknown[]; digest: string }> | null,
  ) =>
    Effect.gen(function* () {
      const connect = custody.connect;
      const integrationId = credential.provider;
      if (connect === undefined || integrationId === undefined)
        return yield* Effect.fail(new ConnectionsError("unsupported"));
      const connectionId = deps.ids();
      const state = `${ownerId}.${deps.ids()}`;
      yield* sync(() => decode(identifier, connectionId));
      const session = yield* connect(
        { ownerId, connectionId, credential },
        { state, actor, integrationId },
      );
      const stored: ConnectionRow = {
        id: connectionId,
        name: draft.name,
        credential,
        locator: null,
        state: "pending",
        authorityVersion: 1,
        version: 1,
        surface: {
          kind: openapi === null ? "mcp" : "openapi",
          url: endpoint,
          table: openapi?.table ?? null,
          digest: openapi?.digest ?? null,
          label: draft.label ?? draft.name,
        },
      };
      return yield* sync(() => {
        store.recordPending({
          actor,
          connection: stored,
          state,
          attemptLocator: null,
          issuer: `custody:${integrationId}`,
          requestId: draft.requestId,
          fingerprint,
          authorizeUrl: session.connectUrl,
        });
        return { connectionId, authorizeUrl: session.connectUrl };
      });
    });

  /**
   * The custodian says an authorization finished. The host has already
   * verified its signature; the state is single use and expiring, and the
   * connection is not live until this settles it.
   */
  const completeCustody = (input: CustodyCompletion) =>
    Effect.gen(function* () {
      const claimed = yield* sync(() => store.claimCustody(input.state));
      if (claimed.expired)
        return yield* Effect.fail(new ConnectionsError("denied"));
      if (claimed.attempt.issuer !== `custody:${input.integrationId}`)
        return yield* Effect.fail(new ConnectionsError("denied"));
      const row = yield* sync(() =>
        store.connection(claimed.attempt.connectionId),
      );
      const activated = yield* sync(() =>
        store.activate(row, claimed.attempt, input.locator),
      );
      if (!activated) {
        yield* sync(() => {
          store.discard(row.id, input.locator, row.credential);
        });
        return yield* Effect.fail(new ConnectionsError("revoked"));
      }
      yield* deps.sweep();
      return { connectionId: row.id };
    });

  const begin = (
    actor: string,
    draft: ConnectionDraft,
    credential: Extract<ConnectionDraft["credential"], { kind: "oauth" }>,
    endpoint: string,
    fingerprint: string,
    /** The decoded operation table of a REST connection, when that is what signs in. */
    openapi: Readonly<{ table: readonly unknown[]; digest: string }> | null,
  ) =>
    Effect.gen(function* () {
      const ports = yield* sync(oauthPorts);
      const connectionId = deps.ids();
      const state = `${ownerId}.${deps.ids()}`;
      yield* sync(() => decode(identifier, connectionId));
      let client: { client_id: string; client_secret?: string } | undefined;
      if (credential.clientId !== undefined) {
        client = { client_id: credential.clientId };
        if (draft.secret !== undefined) client.client_secret = draft.secret;
      }
      const started = yield* io(() => {
        const provider = staticProvider(credential.provider);
        return provider === undefined
          ? startAuthorization({
              serverUrl: endpoint,
              scope: credential.scope,
              client,
              callbackUrl: ports.callbackUrl,
              state,
              registry,
              fetch: guardedFetch,
            })
          : startStaticAuthorization({
              providerId: credential.provider ?? "",
              provider,
              scope: credential.scope,
              callbackUrl: ports.callbackUrl,
              state,
            });
      });
      const attemptLocator = yield* custody.put(
        { ownerId, connectionId, credential },
        Schema.encodeSync(oauthBundleJson)(started.bundle),
      );
      const stored: ConnectionRow = {
        id: connectionId,
        name: draft.name,
        credential,
        locator: null,
        state: "pending",
        authorityVersion: 1,
        version: 1,
        surface: {
          kind: openapi === null ? "mcp" : "openapi",
          url: endpoint,
          table: openapi?.table ?? null,
          digest: openapi?.digest ?? null,
          label: draft.label ?? draft.name,
        },
      };
      return yield* sync(() => {
        store.recordPending({
          actor,
          connection: stored,
          state,
          attemptLocator,
          issuer: started.bundle.authorizationServerUrl,
          requestId: draft.requestId,
          fingerprint,
          authorizeUrl: started.authorizeUrl,
        });
        return { connectionId, authorizeUrl: started.authorizeUrl };
      }).pipe(
        Effect.tapError(() =>
          sync(() => {
            store.discard(connectionId, attemptLocator, credential);
          }),
        ),
      );
    });

  /**
   * The browser's return from the authorization server. The state is single
   * use, expiring and bound to the actor who began; the SDK checks the issuer
   * and PKCE before the code is redeemed.
   */
  const complete = (actor: string, input: CompleteInput) =>
    Effect.gen(function* () {
      const ports = yield* sync(oauthPorts);
      const claimed = yield* sync(() => store.claim(actor, input));
      if (claimed.expired)
        return yield* Effect.fail(new ConnectionsError("denied"));
      const { attempt, wanted } = claimed;
      const row = yield* sync(() => store.connection(attempt.connectionId));
      const attemptLocator = attempt.pkceVerifierSealed ?? "";
      const settled = Effect.gen(function* () {
        const bundle = yield* readBundle(row, attemptLocator);
        const provider = staticProvider(bundle.provider);
        const next = yield* io(() =>
          provider === undefined
            ? finishAuthorization({
                serverUrl: row.surface.url,
                callbackUrl: ports.callbackUrl,
                bundle,
                code: wanted.code,
                iss: wanted.iss,
                now: deps.clock(),
                fetch: guardedFetch,
              })
            : finishStaticAuthorization({
                provider,
                bundle,
                callbackUrl: ports.callbackUrl,
                code: wanted.code,
                iss: wanted.iss,
                now: deps.clock(),
                fetch: guardedFetch,
              }),
        );
        return yield* custody.put(
          address(row),
          Schema.encodeSync(oauthBundleJson)(next),
        );
      }).pipe(
        Effect.tapError(() =>
          sync(() => {
            store.fail(attempt);
          }),
        ),
      );
      const locator = yield* settled;
      const activated = yield* sync(() =>
        store.activate(row, attempt, locator),
      );
      if (!activated) {
        // Revoked while the code was in flight: nothing may come back to life.
        yield* sync(() => {
          store.discard(row.id, locator, row.credential);
        });
        return yield* Effect.fail(new ConnectionsError("revoked"));
      }
      yield* deps.sweep();
      return { connectionId: row.id };
    });

  /** One refresh at a time per connection; later callers share its outcome. */
  const flights = new Map<string, Promise<string>>();
  const refreshLocator = (id: string, stale: string): Promise<string> => {
    const running = flights.get(id);
    if (running !== undefined) return running;
    const flight = Effect.runPromise(refreshOnce(id, stale)).finally(() => {
      flights.delete(id);
    });
    flights.set(id, flight);
    return flight;
  };
  const refreshOnce = (id: string, stale: string) =>
    Effect.gen(function* () {
      const row = yield* sync(() => store.connection(id));
      if (row.state === "revoked")
        return yield* Effect.fail(new ConnectionsError("revoked"));
      if (row.state !== "active" || row.locator === null)
        return yield* Effect.fail(new ConnectionsError("reconnect_required"));
      // A flight that just ended already replaced the token this caller saw.
      if (row.locator !== stale) return row.locator;
      const held = row.locator;
      const bundle = yield* readBundle(row, held);
      const provider = staticProvider(bundle.provider);
      const next = yield* io(() =>
        provider === undefined
          ? refreshTokens({ bundle, now: deps.clock(), fetch: guardedFetch })
          : refreshStaticTokens({
              provider,
              bundle,
              now: deps.clock(),
              fetch: guardedFetch,
            }),
      );
      // Persist the rotated token before anything uses it.
      const locator = yield* custody.put(
        address(row),
        Schema.encodeSync(oauthBundleJson)(next),
      );
      const outcome = yield* sync(() => store.swap(row, held, locator));
      if (outcome !== "applied") {
        // Revoked or replaced during the refresh: the new token never lives.
        yield* sync(() => {
          store.discard(id, locator, row.credential);
        });
        return yield* Effect.fail(
          new ConnectionsError(outcome === "revoked" ? "revoked" : "conflict"),
        );
      }
      return locator;
    });
  const unauthorized = (response: Response) =>
    io(async () => {
      await response.body?.cancel();
    });
  /** Send with the live token: refresh early when it is about to expire, and once on a 401. */
  const send = (row: ConnectionRow, request: Request) =>
    Effect.gen(function* () {
      let locator = row.locator;
      if (locator === null)
        return yield* Effect.fail(new ConnectionsError("reconnect_required"));
      const bundle = yield* readBundle(row, locator);
      if (tokenExpired(bundle, deps.clock())) {
        const stale = locator;
        locator = yield* io(() => refreshLocator(row.id, stale));
      }
      const first = yield* custody.inject(
        address(row),
        locator,
        request.clone(),
      );
      if (first.status !== 401) return first;
      yield* unauthorized(first);
      const stale = locator;
      const fresh = yield* io(() => refreshLocator(row.id, stale));
      const second = yield* custody.inject(
        address(row),
        fresh,
        request.clone(),
      );
      if (second.status !== 401) return second;
      yield* unauthorized(second);
      return yield* Effect.fail(new ConnectionsError("reconnect_required"));
    });

  return { begin, beginCustody, complete, completeCustody, send };
}
