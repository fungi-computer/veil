import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  configuredConnectionsCustody,
  configuredConnectionsOAuthIntegrations,
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
  NANGO_CONNECTIONS_OAUTH_INTEGRATIONS: "gh, notion ,",
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
    expect(configuredConnectionsOAuthIntegrations({})).toEqual([]);
    expect(configuredConnectionsCustody(bindings)).toBeDefined();
    expect(configuredConnectionsOAuthIntegrations(bindings)).toEqual([
      "gh",
      "notion",
    ]);
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
});
