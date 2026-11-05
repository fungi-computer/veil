import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import {
  ConnectionsError,
  type CustodyAddress,
  type CustodyLookup,
} from "./connections/contract.js";
import {
  createNangoCustody,
  type NangoCustodyOptions,
} from "./connections/nango.js";
import { createNangoCustodyHttp } from "./nango-custody-http.js";

const tokenResponse = Schema.Struct({
  credentials: Schema.Struct({
    access_token: Schema.NonEmptyString,
    expires_at: Schema.optional(Schema.String),
  }),
});

/** A completion Nango signed for the GitHub App sign-in, once verified. */
export type GitHubAppCompletion = Readonly<{
  teamId: string;
  state: string;
  principalId: string;
  locator: string;
}>;

/**
 * Nango's `github-app` integration as the one source of a Computer's GitHub
 * token. Nango holds the App's credentials and returns an installation token
 * limited to the repositories the person picked at install. The token is read
 * here, in memory, to be placed on a request to `github.com`; it is never
 * stored, listed or sent anywhere else.
 */
export function createGitHubAppCustody(
  options: NangoCustodyOptions & Readonly<{ appIntegrationId: string }>,
) {
  const nango = createNangoCustody(options);
  const http = createNangoCustodyHttp(options);
  const address = (ownerId: string): CustodyAddress => ({
    ownerId,
    connectionId: "github-app",
    credential: { kind: "oauth", provider: options.appIntegrationId },
  });
  const run = <A>(effect: Effect.Effect<A, ConnectionsError>) =>
    Effect.runPromise(effect);
  const connect = nango.connect;
  if (connect === undefined) throw new ConnectionsError("unsupported");
  const find = nango.find;
  if (find === undefined) throw new ConnectionsError("unsupported");
  return {
    integrationId: options.appIntegrationId,
    /** The page that sends the member to GitHub's installation consent. */
    connect: (ownerId: string, session: { state: string; actor: string }) =>
      run(
        connect(address(ownerId), {
          ...session,
          integrationId: options.appIntegrationId,
        }),
      ),
    /** The signed completion, and only one for this App integration. */
    verifyCompletion: async (
      rawBody: string,
      signature: string,
    ): Promise<GitHubAppCompletion> => {
      const verified = await nango.verifyCompletion(rawBody, signature);
      if (verified.integrationId !== options.appIntegrationId)
        throw new ConnectionsError("denied");
      return {
        teamId: verified.ownerId,
        state: verified.state,
        principalId: verified.principalId,
        locator: verified.locator,
      };
    },
    /** Ask Nango whether a sign-in finished whose signed completion was lost. */
    find: (
      ownerId: string,
      session: { state: string; actor: string },
    ): Promise<CustodyLookup> =>
      run(
        find(address(ownerId), {
          ...session,
          integrationId: options.appIntegrationId,
        }),
      ),
    remove: (ownerId: string, locator: string) =>
      run(nango.remove(address(ownerId), locator)),
    /**
     * A current installation token. `fresh` asks Nango to refresh it first.
     * A connection Nango no longer holds, or whose App access GitHub ended,
     * is `reconnect_required`; an outage is `unavailable`.
     */
    token: async (
      locator: string,
      fresh: boolean,
      signal: AbortSignal,
    ): Promise<string> => {
      const query = new URLSearchParams({
        provider_config_key: options.appIntegrationId,
      });
      if (fresh) query.set("force_refresh", "true");
      let response: Response;
      try {
        response = await http.call(
          `/connection/${encodeURIComponent(locator)}?${query.toString()}`,
          signal,
          {},
        );
      } catch (cause) {
        throw new ConnectionsError("unavailable", { cause });
      }
      if ([400, 401, 403, 404].includes(response.status)) {
        await response.body?.cancel();
        throw new ConnectionsError("reconnect_required");
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw new ConnectionsError("unavailable");
      }
      try {
        return Schema.decodeUnknownSync(Schema.fromJsonString(tokenResponse))(
          await response.text(),
        ).credentials.access_token;
      } catch (cause) {
        throw new ConnectionsError("invalid_response", { cause });
      }
    },
  };
}
export type GitHubAppCustody = ReturnType<typeof createGitHubAppCustody>;
