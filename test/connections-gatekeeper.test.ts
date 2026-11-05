import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  configuredConnectionsCustody,
  configuredConnectionsCustodyProviders,
  configuredGitHubAppCustody,
  configuredGitHubAppIntegration,
  verifyVeilWebhook,
} from "../src/gatekeeper.js";
import { VeilError } from "../src/index.js";

const bindings = {
  NANGO_SERVER_URL: "https://nango.example",
  NANGO_API_KEY: "synthetic-host-key",
  NANGO_WEBHOOK_SIGNING_KEY: "synthetic-signing-key",
  NANGO_CONNECT_BASE_URL: "https://connect.nango.example/",
  NANGO_PUBLIC_API_URL: "https://api.nango.example",
  NANGO_CONNECTIONS_INTEGRATION_ID: "api-key",
  NANGO_CONNECTIONS_OAUTH_INTEGRATIONS: JSON.stringify({
    gh: { apiOrigins: ["https://api.github.com"] },
    notion: { apiOrigins: ["https://api.notion.com"] },
    // An entry that is not an https origin is dropped, never widened.
    loose: { apiOrigins: ["https://api.loose.example/v1"] },
  }),
} as const;
const signed = (body: string) =>
  createHmac("sha256", bindings.NANGO_WEBHOOK_SIGNING_KEY)
    .update(body)
    .digest("hex");
const completion = JSON.stringify({
  type: "auth",
  operation: "creation",
  success: true,
  connectionId: "nango-conn-1",
  providerConfigKey: "gh",
  tags: {
    veil_team_id: "team-1",
    veil_attempt_id: "team-1.attempt",
    veil_principal_id: "owner",
  },
  endUser: { endUserId: "owner", organizationId: "team-1" },
});

describe("optional Nango custody for connections", () => {
  it("is absent without its bindings, and a Hub then keeps sealed custody", () => {
    expect(configuredConnectionsCustody({})).toBeUndefined();
    expect(
      configuredConnectionsCustody(
        Object.fromEntries(
          Object.entries(bindings).filter(
            ([name]) => name !== "NANGO_CONNECTIONS_INTEGRATION_ID",
          ),
        ),
      ),
    ).toBeUndefined();
    expect(configuredConnectionsCustodyProviders({})).toEqual({});
    expect(configuredConnectionsCustody(bindings)).toBeDefined();
    expect(configuredConnectionsCustodyProviders(bindings)).toEqual({
      gh: { apiOrigins: ["https://api.github.com"] },
      notion: { apiOrigins: ["https://api.notion.com"] },
    });
    // An id list without origins pins nothing, so it admits nothing.
    expect(
      configuredConnectionsCustodyProviders({
        NANGO_CONNECTIONS_OAUTH_INTEGRATIONS: "gh, notion",
      }),
    ).toEqual({});
  });

  it("names the Team a verified sign-in belongs to, and believes nothing unsigned", async () => {
    expect(
      await verifyVeilWebhook(bindings, completion, signed(completion)),
    ).toEqual({ profile: "connections", ownerId: "team-1" });
    await expect(
      verifyVeilWebhook(bindings, completion, "0".repeat(64)),
    ).rejects.toMatchObject({ code: "invalid_completion" });
    // An integration the operator did not list for connections is not ours.
    const other = completion.replace('"gh"', '"unlisted"');
    await expect(
      verifyVeilWebhook(bindings, other, signed(other)),
    ).rejects.toBeInstanceOf(VeilError);
  });

  it("pins GitHub REST to api.github.com and keeps the GitHub App apart from it", async () => {
    const github = {
      ...bindings,
      NANGO_GITHUB_INTEGRATION_ID: "github-rest",
      NANGO_GITHUB_APP_INTEGRATION_ID: "github-app",
    };
    expect(
      configuredConnectionsCustodyProviders(github)["github-rest"],
    ).toEqual({
      apiOrigins: ["https://api.github.com"],
    });
    // The App integration serves Computers only; it is never a generic one.
    expect(
      configuredConnectionsCustodyProviders(github)["github-app"],
    ).toBeUndefined();
    expect(configuredGitHubAppIntegration(github)).toBe("github-app");
    expect(configuredGitHubAppIntegration(bindings)).toBeUndefined();
    expect(configuredGitHubAppCustody(github)).toBeDefined();
    expect(configuredGitHubAppCustody(bindings)).toBeUndefined();
    // The same integration cannot be both GitHub REST and the GitHub App.
    const same = { ...github, NANGO_GITHUB_APP_INTEGRATION_ID: "github-rest" };
    expect(configuredGitHubAppIntegration(same)).toBeUndefined();
    // An operator entry cannot widen the App integration into a generic one.
    const widened = {
      ...github,
      NANGO_CONNECTIONS_OAUTH_INTEGRATIONS: JSON.stringify({
        "github-app": { apiOrigins: ["https://evil.example"] },
      }),
    };
    expect(
      configuredConnectionsCustodyProviders(widened)["github-app"],
    ).toBeUndefined();
    const rest = completion.replace('"gh"', '"github-rest"');
    expect(await verifyVeilWebhook(github, rest, signed(rest))).toEqual({
      profile: "connections",
      ownerId: "team-1",
    });
    const app = completion.replace('"gh"', '"github-app"');
    expect(await verifyVeilWebhook(github, app, signed(app))).toEqual({
      profile: "computer-git",
      ownerId: "team-1",
    });
    expect(await verifyVeilWebhook(widened, app, signed(app))).toEqual({
      profile: "computer-git",
      ownerId: "team-1",
    });
  });
});
