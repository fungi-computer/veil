import { createHmac } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { ConnectionsError } from "../src/connections/contract.js";
import { createGitHubAppCustody } from "../src/github-app.js";

afterEach(() => vi.unstubAllGlobals());

const options = {
  serverUrl: "https://nango.example",
  apiKey: "synthetic-host-key",
  webhookSigningKey: "synthetic-signing-key",
  staticIntegrationId: "api-key",
  connectBaseUrl: "https://connect.nango.example/",
  publicApiUrl: "https://api.nango.example",
  appIntegrationId: "github-app",
} as const;
const signal = () => new AbortController().signal;

const stub = (respond: (url: URL) => Response) => {
  const seen: URL[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: string | URL | Request) => {
      const url = new URL(input instanceof Request ? input.url : input);
      seen.push(url);
      return Promise.resolve(respond(url));
    }),
  );
  return seen;
};
const installation = (token = "ghs_installation") =>
  Response.json({ credentials: { type: "APP", access_token: token } });

it("reads Nango's current installation token for this App integration only", async () => {
  const seen = stub(() => installation());
  const app = createGitHubAppCustody(options);
  expect(await app.token("conn-1", false, signal())).toBe("ghs_installation");
  expect(seen[0]?.pathname).toBe("/connection/conn-1");
  expect(seen[0]?.searchParams.get("provider_config_key")).toBe("github-app");
  expect(seen[0]?.searchParams.has("force_refresh")).toBe(false);
  await app.token("conn-1", true, signal());
  expect(seen[1]?.searchParams.get("force_refresh")).toBe("true");
});

it("treats a connection Nango lost as reconnect-required, an outage as unavailable, and an odd body as invalid", async () => {
  const app = createGitHubAppCustody(options);
  const outcome = async () => {
    try {
      await app.token("conn-1", false, signal());
      return "ok";
    } catch (error) {
      return error instanceof ConnectionsError ? error.code : "unexpected";
    }
  };
  for (const [status, code] of [
    [404, "reconnect_required"],
    [401, "reconnect_required"],
    [500, "unavailable"],
  ] as const) {
    stub(() => new Response("{}", { status }));
    expect(await outcome()).toBe(code);
  }
  stub(() => Response.json({ credentials: {} }));
  expect(await outcome()).toBe("invalid_response");
});

it("settles only a signed completion for its own integration", async () => {
  const app = createGitHubAppCustody(options);
  const completion = (integration: string) =>
    JSON.stringify({
      type: "auth",
      operation: "creation",
      success: true,
      connectionId: "conn-1",
      providerConfigKey: integration,
      tags: {
        veil_team_id: "team-1",
        veil_attempt_id: "team-1.attempt",
        veil_principal_id: "member-1",
      },
      endUser: { endUserId: "member-1", organizationId: "team-1" },
    });
  const sign = (body: string) =>
    createHmac("sha256", options.webhookSigningKey).update(body).digest("hex");
  const own = completion("github-app");
  expect(await app.verifyCompletion(own, sign(own))).toEqual({
    teamId: "team-1",
    state: "team-1.attempt",
    principalId: "member-1",
    locator: "conn-1",
  });
  const other = completion("github-rest");
  await expect(app.verifyCompletion(other, sign(other))).rejects.toMatchObject({
    code: "denied",
  });
  await expect(app.verifyCompletion(own, "0".repeat(64))).rejects.toThrow();
});
