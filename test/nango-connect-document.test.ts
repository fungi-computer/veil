import { afterEach, expect, it, vi } from "vitest";
import { createNangoCustodian } from "../src/nango.js";

const publicUrls = {
  connectBaseUrl: "https://connect.example.test/ui",
  publicApiUrl: "https://connect.example.test/api",
};
const issued = {
  token: "synthetic-session",
  connectLink:
    "https://connect.example.test/ui/?session_token=synthetic-session&theme=dark",
};
const input = {
  teamId: "team-a",
  attemptId: "attempt-a",
  principalId: "user-a",
  integrationId: "github-git",
};

afterEach(() => vi.unstubAllGlobals());

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
    custody: createNangoCustodian({
      serverUrl: "http://nango.internal:3003",
      apiKey: "synthetic-key",
      webhookSigningKey: "synthetic-signing-key",
      integrationId: "github-git",
      ...urls,
    }),
  };
}

it("issues the Connect document for the explicit public API, not internal custody", async () => {
  const { custody: adapter, request } = custody();
  const session = await adapter.openSession(
    input,
    new AbortController().signal,
  );
  const document = new URL(session.connectUrl);
  expect(document.origin + document.pathname).toBe(
    "https://connect.example.test/ui/",
  );
  expect(document.searchParams.get("apiURL")).toBe(publicUrls.publicApiUrl);
  expect(document.searchParams.get("session_token")).toBe(session.token);
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
    await expect(
      custody(connectLink).custody.openSession(
        input,
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code: "invalid_response" });
  },
);

it("replaces an issued API selector with trusted configuration", async () => {
  const session = await custody(
    issued.connectLink + "&apiURL=https://other.test",
  ).custody.openSession(input, new AbortController().signal);
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
