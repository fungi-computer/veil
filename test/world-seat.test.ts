import { afterEach, expect, it, vi } from "vitest";
import { configuredWorldSeatEndpoint } from "../src/gatekeeper.js";
import { createNangoWorldSeatCustodian } from "../src/nango-world-seat.js";
import {
  worldSeatEndpoint,
  worldSeatForwardedHeaders,
  worldSeatTarget,
} from "../src/world-seat.js";

afterEach(() => vi.unstubAllGlobals());

const canary = "world-canary-0123456789abcdefghijklmnop";
const endpoint = "https://vishnu.shiit.app/mcp";
const custodian = createNangoWorldSeatCustodian({
  serverUrl: "https://nango.example",
  apiKey: "synthetic-host-key",
  integrationId: "vishnu-world",
});

it("accepts only a public HTTPS /mcp endpoint with no credentials", () => {
  expect(worldSeatEndpoint(endpoint)).toBe(endpoint);
  for (const bad of [
    "http://vishnu.shiit.app/mcp",
    "http://127.0.0.1:8080/mcp",
    "https://127.0.0.1/mcp",
    "https://localhost/mcp",
    "https://vishnu.internal/mcp",
    "https://user:pass@vishnu.shiit.app/mcp",
    "https://vishnu.shiit.app/mcp?key=1",
    "https://vishnu.shiit.app/other",
    "not a url",
  ])
    expect(() => worldSeatEndpoint(bad), bad).toThrow();
});

it("confines a call to the seat's endpoint and the MCP verbs", () => {
  const access = { locator: "wsloc_1", endpoint };
  expect(
    worldSeatTarget(access, new Request(endpoint, { method: "POST" })).href,
  ).toBe(endpoint);
  for (const url of [
    "https://other.example/mcp",
    "https://vishnu.shiit.app/mcp/extra",
    "https://vishnu.shiit.app/mcp?x=1",
  ])
    expect(() => worldSeatTarget(access, new Request(url))).toThrow();
  expect(() =>
    worldSeatTarget(access, new Request(endpoint, { method: "PUT" })),
  ).toThrow();
  const headers = worldSeatForwardedHeaders(
    new Request(endpoint, {
      headers: {
        authorization: "Bearer caller",
        "mcp-session-id": "s1",
        accept: "text/event-stream",
      },
    }),
  );
  expect(headers.get("authorization")).toBeNull();
  expect(headers.get("mcp-session-id")).toBe("s1");
});

it("seals a token into Nango under a private locator and returns nothing", async () => {
  vi.stubGlobal("fetch", (input: URL, init: RequestInit) => {
    expect(input.href).toBe("https://nango.example/connections");
    expect(new Headers(init.headers).get("Authorization")).toBe(
      "Bearer synthetic-host-key",
    );
    // SAFETY: the adapter serializes its import body with JSON.stringify.
    expect(JSON.parse(init.body as string)).toEqual({
      provider_config_key: "vishnu-world",
      connection_id: "wsloc_1",
      credentials: { type: "API_KEY", apiKey: canary },
      tags: { veil_team_id: "team_1" },
    });
    return Promise.resolve(Response.json({ connection_id: "wsloc_1" }));
  });
  await expect(
    custodian.seal(
      { teamId: "team_1", locator: "wsloc_1", endpoint, token: canary },
      new AbortController().signal,
    ),
  ).resolves.toBeUndefined();
});

it("proxies MCP calls through Nango to the seat's endpoint only", async () => {
  vi.stubGlobal("fetch", (input: URL, init: RequestInit) => {
    expect(input.href).toBe("https://nango.example/proxy/mcp");
    const headers = new Headers(init.headers);
    expect(headers.get("Authorization")).toBe("Bearer synthetic-host-key");
    expect(headers.get("Connection-Id")).toBe("wsloc_1");
    expect(headers.get("Provider-Config-Key")).toBe("vishnu-world");
    expect(headers.get("Base-Url-Override")).toBe("https://vishnu.shiit.app");
    expect(headers.get("Nango-Proxy-mcp-session-id")).toBe("s1");
    expect(headers.get("Nango-Proxy-authorization")).toBeNull();
    expect(init.redirect).toBe("manual");
    return Promise.resolve(Response.json({ ok: true }));
  });
  const response = await custodian.send(
    { locator: "wsloc_1", endpoint },
    new Request(endpoint, {
      method: "POST",
      headers: {
        authorization: "Bearer caller-supplied",
        "content-type": "application/json",
        "mcp-session-id": "s1",
      },
      body: "{}",
    }),
  );
  expect(response.status).toBe(200);
  await expect(
    custodian.send(
      { locator: "wsloc_1", endpoint },
      new Request("https://evil.example/mcp", { method: "POST", body: "{}" }),
    ),
  ).rejects.toMatchObject({ code: "denied" });
});

it("settles removal only on a confirmed or absent connection", async () => {
  const answers = [
    Response.json({ success: true }),
    Response.json({ error: { code: "unknown_connection" } }, { status: 400 }),
    new Response("boom", { status: 500 }),
  ];
  vi.stubGlobal("fetch", () => Promise.resolve(answers.shift()));
  const signal = new AbortController().signal;
  await expect(custodian.remove({ locator: "wsloc_1" }, signal)).resolves.toBe(
    "deleted",
  );
  await expect(custodian.remove({ locator: "wsloc_1" }, signal)).resolves.toBe(
    "absent",
  );
  await expect(
    custodian.remove({ locator: "wsloc_1" }, signal),
  ).rejects.toMatchObject({ code: "unavailable" });
});

it("refuses plain HTTP to any Nango that is not loopback", () => {
  expect(() =>
    createNangoWorldSeatCustodian({
      serverUrl: "http://nango.example",
      apiKey: "k",
      integrationId: "i",
    }),
  ).toThrow();
  expect(() =>
    createNangoWorldSeatCustodian({
      serverUrl: "http://127.0.0.1:3003",
      apiKey: "k",
      integrationId: "i",
    }),
  ).not.toThrow();
});

it("admits a loopback endpoint only when the host's explicit local flag is on", () => {
  const loopback = [
    "http://127.0.0.1:8080/mcp",
    "http://localhost:8080/mcp",
    "http://[::1]:8080/mcp",
    "https://127.0.0.1/mcp",
  ];
  // Production mode (the default): every loopback form is refused.
  const production = configuredWorldSeatEndpoint({});
  for (const url of loopback) expect(() => production(url), url).toThrow();
  // Only the exact value enabled is local mode; nothing else turns it on.
  for (const flag of ["true", "on", "1", "ENABLED", "off", ""])
    expect(() =>
      configuredWorldSeatEndpoint({ HUB_LOCAL_MODE: flag })(
        "http://127.0.0.1:8080/mcp",
      ),
    ).toThrow();
  const local = configuredWorldSeatEndpoint({ HUB_LOCAL_MODE: "enabled" });
  for (const url of loopback) expect(local(url)).toBe(url);
  // Local mode is not a general relaxation: the rest of the rule stays.
  for (const bad of [
    "http://vishnu.shiit.app/mcp",
    "http://10.0.0.5/mcp",
    "http://127.0.0.1:8080/other",
    "http://user:pass@127.0.0.1/mcp",
    "http://127.0.0.1/mcp?x=1",
    "ftp://127.0.0.1/mcp",
  ])
    expect(() => local(bad), bad).toThrow();
  expect(local(endpoint)).toBe(endpoint);
});

it("seals a loopback seat only for a local-mode custodian", async () => {
  vi.stubGlobal("fetch", () =>
    Promise.resolve(Response.json({ connection_id: "wsloc_1" })),
  );
  const input = {
    teamId: "team_1",
    locator: "wsloc_1",
    endpoint: "http://127.0.0.1:8080/mcp",
    token: canary,
  };
  const signal = new AbortController().signal;
  await expect(custodian.seal(input, signal)).rejects.toMatchObject({
    code: "invalid_input",
  });
  const local = createNangoWorldSeatCustodian({
    serverUrl: "https://nango.example",
    apiKey: "synthetic-host-key",
    integrationId: "vishnu-world",
    allowLocalDev: true,
  });
  await expect(local.seal(input, signal)).resolves.toBeUndefined();
});
