import { afterEach, expect, it, vi } from "vitest";
import {
  credentialUsableBy,
  loginAllowed,
  modelCredentialPermission,
  type CredentialHost,
  type CredentialMethod,
} from "../src/model-credentials.js";
import {
  modelKeyBaseUrl,
  modelKeyTarget,
  modelKeyValidationRequest,
  modelKeyValidationResult,
} from "../src/model-keys.js";
import { createNangoModelKeyCustodian } from "../src/nango-model-keys.js";

afterEach(() => vi.unstubAllGlobals());

const canary = "sk-canary-0123456789abcdefghijklmnop";
const custodian = createNangoModelKeyCustodian({
  serverUrl: "https://nango.example",
  apiKey: "synthetic-host-key",
  integrations: {
    anthropic: "anthropic-key",
    openai: "openai-key",
    "openai-compatible": "compatible-key",
  },
});

it("records one per-provider policy for local and hosted credentials", () => {
  const allowed = (
    providerId: string,
    method: "api_key" | "subscription",
    host: "local" | "hosted",
  ) => loginAllowed({ providerId, method, host, scope: "user" });
  expect(allowed("anthropic", "api_key", "hosted")).toBe(true);
  expect(allowed("anthropic", "subscription", "local")).toBe(true);
  expect(allowed("anthropic", "subscription", "hosted")).toBe(false);
  expect(
    modelCredentialPermission("anthropic", "subscription", "hosted"),
  ).toEqual({
    status: "forbidden",
    reason: "Fungi does not offer this credential method on this host",
    source: "wiki/3-resources/decisions/adr-byok-model-keys-v1.md",
  });
  for (const host of ["local", "hosted"] as const)
    expect(modelCredentialPermission("fungi", "api_key", host)).toEqual(
      modelCredentialPermission("anthropic", "subscription", "hosted"),
    );
  for (const providerId of ["openrouter", "openai-compatible"])
    for (const host of ["local", "hosted"] as const)
      expect(
        modelCredentialPermission(providerId, "subscription", host),
      ).toEqual({
        status: "forbidden",
        reason: "The provider does not offer this credential method",
        source: "provider documentation",
      });
  expect(allowed("openai-codex", "subscription", "local")).toBe(false);
  expect(allowed("openai-codex", "subscription", "hosted")).toBe(false);
  expect(
    modelCredentialPermission("github-copilot", "subscription", "local"),
  ).toEqual({ status: "unreviewed" });
  expect(allowed("github-copilot", "subscription", "local")).toBe(true);
  expect(allowed("github-copilot", "subscription", "hosted")).toBe(false);
  expect(allowed("toString", "api_key", "hosted")).toBe(false);
});

it("turns a provider's subscription off everywhere with its kill switch", () => {
  const off = { anthropic: true };
  for (const host of ["local", "hosted"] as const)
    expect(
      loginAllowed(
        {
          providerId: "anthropic",
          method: "subscription",
          host,
          scope: "user",
        },
        off,
      ),
    ).toBe(false);
  expect(
    loginAllowed(
      {
        providerId: "anthropic",
        method: "api_key",
        host: "hosted",
        scope: "user",
      },
      off,
    ),
  ).toBe(true);
});

it("never lets a subscription be Team-scoped, shared or pooled", () => {
  for (const providerId of ["anthropic", "openai-codex", "openai"])
    for (const host of ["local", "hosted"] as const)
      expect(
        loginAllowed({
          providerId,
          method: "subscription",
          host,
          scope: "team",
        }),
      ).toBe(false);
  expect(
    loginAllowed({
      providerId: "openai",
      method: "api_key",
      host: "hosted",
      scope: "team",
    }),
  ).toBe(true);
});

it("binds a user credential to that user and their own Agents and Computers", () => {
  const mine = { scope: "user", teamId: "team_1", userId: "user_a" } as const;
  const team = { scope: "team", teamId: "team_1" } as const;
  expect(
    credentialUsableBy(mine, {
      teamId: "team_1",
      kind: "user",
      userId: "user_a",
    }),
  ).toBe(true);
  expect(
    credentialUsableBy(mine, {
      teamId: "team_1",
      kind: "agent",
      ownerUserId: "user_a",
    }),
  ).toBe(true);
  expect(
    credentialUsableBy(mine, {
      teamId: "team_1",
      kind: "computer",
      ownerUserId: "user_a",
    }),
  ).toBe(true);
  // Another member, their Agent, a Team key and another Team are refused.
  expect(
    credentialUsableBy(mine, {
      teamId: "team_1",
      kind: "user",
      userId: "user_b",
    }),
  ).toBe(false);
  expect(
    credentialUsableBy(mine, {
      teamId: "team_1",
      kind: "agent",
      ownerUserId: "user_b",
    }),
  ).toBe(false);
  expect(credentialUsableBy(mine, { teamId: "team_1", kind: "team-key" })).toBe(
    false,
  );
  expect(
    credentialUsableBy(mine, {
      teamId: "team_2",
      kind: "user",
      userId: "user_a",
    }),
  ).toBe(false);
  expect(credentialUsableBy(team, { teamId: "team_1", kind: "team-key" })).toBe(
    true,
  );
  expect(credentialUsableBy(team, { teamId: "team_2", kind: "team-key" })).toBe(
    false,
  );
});

it("confines base URLs and supplier targets below the sealed key", () => {
  expect(modelKeyBaseUrl("openai")).toBe("https://api.openai.com/v1");
  expect(() => modelKeyBaseUrl("openai", "https://evil.example")).toThrow();
  expect(modelKeyBaseUrl("openai-compatible", "https://llm.example/v1/")).toBe(
    "https://llm.example/v1",
  );
  for (const bad of [
    "http://llm.example/v1",
    "https://user:pass@llm.example/v1",
    "https://llm.example/v1?key=1",
    "not a url",
  ])
    expect(() => modelKeyBaseUrl("openai-compatible", bad)).toThrow();
  const access = {
    locator: "key_1",
    provider: "openai-compatible" as const,
    baseUrl: "https://llm.example/v1",
  };
  expect(
    modelKeyTarget(
      access,
      new Request("https://llm.example/v1/chat/completions", {
        method: "POST",
      }),
    ).pathname,
  ).toBe("/v1/chat/completions");
  for (const url of [
    "https://other.example/v1/chat/completions",
    "https://llm.example/v2/chat/completions",
    "https://llm.example/v1x/models",
  ])
    expect(() => modelKeyTarget(access, new Request(url))).toThrow();
  expect(() =>
    modelKeyTarget(
      access,
      new Request("https://llm.example/v1/models", { method: "DELETE" }),
    ),
  ).toThrow();
});

it("validates with a cheap authenticated read and reads only auth refusals as bad keys", () => {
  const signal = new AbortController().signal;
  expect(
    modelKeyValidationRequest(
      { provider: "anthropic", baseUrl: "https://api.anthropic.com" },
      signal,
    ).url,
  ).toBe("https://api.anthropic.com/v1/models?limit=1");
  expect(
    modelKeyValidationRequest(
      { provider: "openrouter", baseUrl: "https://openrouter.ai/api/v1" },
      signal,
    ).url,
  ).toBe("https://openrouter.ai/api/v1/key");
  expect(modelKeyValidationResult(200)).toBe("valid");
  expect(modelKeyValidationResult(401)).toBe("rejected");
  expect(modelKeyValidationResult(429)).toBe("unavailable");
});

it("seals a key into Nango under a private locator and returns nothing", async () => {
  vi.stubGlobal("fetch", (input: URL, init: RequestInit) => {
    expect(input.href).toBe("https://nango.example/connections");
    expect(new Headers(init.headers).get("Authorization")).toBe(
      "Bearer synthetic-host-key",
    );
    // SAFETY: the adapter serializes its import body with JSON.stringify.
    expect(JSON.parse(init.body as string)).toEqual({
      provider_config_key: "openai-key",
      connection_id: "key_1",
      credentials: { type: "API_KEY", apiKey: canary },
      tags: { veil_team_id: "team_1" },
    });
    return Promise.resolve(
      Response.json({
        connection_id: "key_1",
        credentials: { type: "API_KEY", apiKey: canary },
      }),
    );
  });
  await expect(
    custodian.seal(
      {
        teamId: "team_1",
        locator: "key_1",
        provider: "openai",
        apiKey: canary,
      },
      new AbortController().signal,
    ),
  ).resolves.toBeUndefined();
});

it("proxies supplier calls through Nango without forwarding caller credentials", async () => {
  vi.stubGlobal("fetch", (input: URL, init: RequestInit) => {
    expect(input.href).toBe("https://nango.example/proxy/v1/messages");
    const headers = new Headers(init.headers);
    expect(headers.get("Authorization")).toBe("Bearer synthetic-host-key");
    expect(headers.get("Connection-Id")).toBe("key_1");
    expect(headers.get("Provider-Config-Key")).toBe("anthropic-key");
    expect(headers.get("Base-Url-Override")).toBe("https://api.anthropic.com");
    expect(headers.get("Nango-Proxy-anthropic-version")).toBe("2023-06-01");
    expect(headers.get("Nango-Proxy-x-api-key")).toBeNull();
    expect(headers.get("Nango-Proxy-authorization")).toBeNull();
    expect(init.redirect).toBe("manual");
    return Promise.resolve(
      new Response("data: {}\n\n", {
        headers: { "Content-Type": "text/event-stream" },
      }),
    );
  });
  const response = await custodian.send(
    {
      locator: "key_1",
      provider: "anthropic",
      baseUrl: "https://api.anthropic.com",
    },
    new Request("https://api.anthropic.com/v1/messages", {
      method: "POST",
      body: "{}",
      headers: {
        "content-type": "application/json",
        "anthropic-version": "2023-06-01",
        "x-api-key": "placeholder",
        authorization: "Bearer placeholder",
      },
    }),
  );
  expect(await response.text()).toBe("data: {}\n\n");
});

it("removes a sealed key and reports an absent connection", async () => {
  vi.stubGlobal("fetch", (input: URL, init: RequestInit) => {
    expect(init.method).toBe("DELETE");
    expect(input.href).toBe(
      "https://nango.example/connections/key_1?provider_config_key=openai-key",
    );
    return Promise.resolve(
      Response.json({ error: { code: "unknown_connection" } }, { status: 400 }),
    );
  });
  await expect(
    custodian.remove(
      { locator: "key_1", provider: "openai" },
      new AbortController().signal,
    ),
  ).resolves.toBe("absent");
});

it("refuses a provider without a configured integration before egress", async () => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  await expect(
    custodian.seal(
      {
        teamId: "team_1",
        locator: "key_2",
        provider: "openrouter",
        apiKey: canary,
      },
      new AbortController().signal,
    ),
  ).rejects.toMatchObject({ code: "unavailable" });
  expect(fetch).not.toHaveBeenCalled();
});

it("allows ChatGPT plan usage only for a local user's own subscription", () => {
  const request = {
    providerId: "openai",
    method: "subscription",
    scope: "user",
  } as const;
  expect(loginAllowed({ ...request, host: "local" })).toBe(true);
  expect(loginAllowed({ ...request, host: "hosted" })).toBe(false);
  expect(modelCredentialPermission("openai", "subscription", "hosted")).toEqual(
    {
      status: "forbidden",
      reason:
        "Fungi does not offer ChatGPT subscription sign-in on hosted Fungi; approval alone would not enable it",
      source: "wiki/3-resources/decisions/adr-byok-model-keys-v1.md",
    },
  );
  expect(loginAllowed({ ...request, host: "local" }, { openai: true })).toBe(
    false,
  );
  for (const host of ["local", "hosted"] as const)
    expect(
      loginAllowed({
        providerId: "openai",
        method: "api_key",
        scope: "user",
        host,
      }),
    ).toBe(true);
});

it("keeps the retired Codex provider forbidden for every method and host", () => {
  const methods: readonly CredentialMethod[] = ["api_key", "subscription"];
  const hosts: readonly CredentialHost[] = ["local", "hosted"];
  for (const method of methods)
    for (const host of hosts) {
      expect(
        modelCredentialPermission("openai-codex", method, host).status,
      ).toBe("forbidden");
      expect(
        loginAllowed(
          { providerId: "openai-codex", method, host, scope: "user" },
          {},
        ),
      ).toBe(false);
    }
});
