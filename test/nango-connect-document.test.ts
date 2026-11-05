import { afterEach, expect, it, vi } from "vitest";
import * as Effect from "effect/Effect";
import { createNangoCustody } from "../src/connections/nango.js";

const publicUrls = {
  connectBaseUrl: "https://connect.example.test/ui",
  publicApiUrl: "https://connect.example.test/api",
};
const issued = {
  token: "synthetic-session",
  connectLink:
    "https://connect.example.test/ui/?session_token=synthetic-session&theme=dark",
};
const address = {
  ownerId: "team-a",
  connectionId: "connection-a",
  credential: { kind: "oauth", provider: "github-git" },
} as const;
const input = {
  state: "team-a.attempt-a",
  actor: "user-a",
  integrationId: "github-git",
};

afterEach(() => vi.unstubAllGlobals());

const connect = (
  adapter: ReturnType<typeof createNangoCustody>,
  session = input,
) => Effect.runPromise(adapter.connect?.(address, session) ?? Effect.die(0));
const refusal = (
  adapter: ReturnType<typeof createNangoCustody>,
): Promise<string> =>
  Effect.runPromise(
    Effect.match(adapter.connect?.(address, input) ?? Effect.die(0), {
      onSuccess: () => "ok",
      onFailure: (error) => error.code,
    }),
  );

function custody(
  connectLink = issued.connectLink,
  urls: typeof publicUrls = publicUrls,
) {
  const request = vi.fn(() =>
    Promise.resolve(
      Response.json({
        data: {
          token: issued.token,
          connect_link: connectLink,
          expires_at: new Date(2000000000000).toISOString(),
        },
      }),
    ),
  );
  vi.stubGlobal("fetch", request);
  return {
    request,
    custody: createNangoCustody({
      serverUrl: "https://nango.internal.test",
      apiKey: "synthetic-key",
      webhookSigningKey: "synthetic-signing-key",
      staticIntegrationId: "api-key",
      ...urls,
    }),
  };
}

it("issues the Connect document for the explicit public API, not internal custody", async () => {
  const { custody: adapter, request } = custody();
  const session = await connect(adapter);
  const document = new URL(session.connectUrl);
  expect(document.origin + document.pathname).toBe(
    "https://connect.example.test/ui/",
  );
  expect(document.searchParams.get("apiURL")).toBe(publicUrls.publicApiUrl);
  expect(document.searchParams.get("session_token")).toBe(issued.token);
  expect(document.searchParams.get("theme")).toBe("dark");
  expect(request).toHaveBeenCalledOnce();
});

it.each([
  "https://other.example.test/ui/?session_token=synthetic-session",
  "https://connect.example.test/other/?session_token=synthetic-session",
  "https://connect.example.test/ui/nested?session_token=synthetic-session",
  "https://connect.example.test/ui/?session_token=different",
  "https://connect.example.test/ui/",
  "https://user@connect.example.test/ui/?session_token=synthetic-session",
])(
  "rejects an issued document outside the configured Connect UI (%s)",
  async (connectLink) => {
    expect(await refusal(custody(connectLink).custody)).toBe(
      "invalid_response",
    );
  },
);

it("replaces an issued API selector with trusted configuration", async () => {
  const session = await connect(
    custody(issued.connectLink + "&apiURL=https://other.test").custody,
  );
  expect(new URL(session.connectUrl).searchParams.getAll("apiURL")).toEqual([
    publicUrls.publicApiUrl,
  ]);
});

it("rejects configuration query instead of treating it as an API binding", () => {
  expect(() =>
    custody(issued.connectLink, {
      ...publicUrls,
      connectBaseUrl: publicUrls.connectBaseUrl + "?apiURL=https://other.test",
    }),
  ).toThrow("invalid_input");
});

const attempt = {
  state: "team-a.attempt-a",
  actor: "user-a",
  integrationId: "github-git",
};
const listed = (
  rows: readonly { id: string; tags?: Record<string, string> }[],
) =>
  Response.json({
    connections: rows.map(({ id, tags }) => ({
      connection_id: id,
      provider_config_key: "github-git",
      tags: {
        veil_team_id: "team-a",
        veil_attempt_id: attempt.state,
        veil_principal_id: "user-a",
        ...tags,
      },
      end_user: { id: "user-a", organization: { id: "team-a" } },
    })),
  });
const lookup = async (rows: Parameters<typeof listed>[0]) => {
  const asked: string[] = [];
  const request = vi.fn((input: string | URL | Request) => {
    asked.push(input instanceof Request ? input.url : String(input));
    return Promise.resolve(listed(rows));
  });
  const adapter = custody().custody;
  vi.stubGlobal("fetch", request);
  const outcome = await Effect.runPromise(
    Effect.result(adapter.find?.(address, attempt) ?? Effect.die(0)),
  );
  return { requested: () => asked[0] ?? "", outcome };
};

it("asks Nango for exactly this attempt's connection when its webhook was lost", async () => {
  const found = await lookup([{ id: "nango-1" }]);
  expect(found.outcome).toMatchObject({
    _tag: "Success",
    success: { status: "found", locator: "nango-1" },
  });
  const url = new URL(found.requested());
  expect(url.pathname).toBe("/connections");
  expect(url.searchParams.get("tags[veil_attempt_id]")).toBe(attempt.state);
  expect(url.searchParams.get("endUserOrganizationId")).toBe("team-a");
  expect(url.searchParams.get("limit")).toBe("2");
  expect((await lookup([])).outcome).toMatchObject({
    _tag: "Success",
    success: { status: "unresolved" },
  });
  expect((await lookup([{ id: "a" }, { id: "b" }])).outcome).toMatchObject({
    _tag: "Success",
    success: { status: "ambiguous" },
  });
  // A row that does not match the attempt is never believed.
  const foreign = await lookup([
    { id: "nango-1", tags: { veil_attempt_id: "other" } },
  ]);
  expect(foreign.outcome._tag).toBe("Failure");
});
