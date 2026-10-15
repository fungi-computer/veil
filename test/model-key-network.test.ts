import { expect, it } from "vitest";
import {
  assertPublicHostName,
  assertPublicResolution,
  canonicalAddress,
  createDnsOverHttpsResolver,
  publicAddress,
  resolvePublicAddresses,
} from "../src/model-key-network.js";
import {
  loginAllowed,
  subscriptionKillSwitchFrom,
} from "../src/model-credentials.js";
import { modelKeyBaseUrl } from "../src/model-keys.js";

it("classifies private, loopback, link-local, metadata and mapped addresses as inward", () => {
  for (const address of [
    "10.0.0.5",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.4.2",
    "192.168.1.1",
    "100.64.0.1",
    "0.0.0.0",
    "::1",
    "fe80::1",
    "fc00::1",
    "fec0::1",
    "::ffff:0:7f00:1",
    "2001:2::1",
    "2001:10::1",
    "2001:1f::1",
    "::ffff:127.0.0.1",
    "64:ff9b::a00:5",
    "::127.0.0.1",
    "::7f00:1",
    "::ffff:7f00:1",
    "::ffff:a9fe:a9fe",
    "64:ff9b::7f00:1",
    "64:ff9b:1::1",
    "2002:7f00:1::",
    "2002:a00:5::1",
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    "192.88.99.1",
  ])
    expect(publicAddress(address), address).toBe(false);
  expect(publicAddress("93.184.216.34")).toBe(true);
  expect(publicAddress("2606:4700::1111")).toBe(true);
  expect(publicAddress("::ffff:93.184.216.34")).toBe(true);
  expect(publicAddress("2002:5db8:d822::1")).toBe(true);
  expect(publicAddress("llm.example.com")).toBeNull();
});

it("gives one canonical text for an address and none for a name", () => {
  expect(canonicalAddress("93.184.216.34")).toBe("93.184.216.34");
  expect(canonicalAddress("[2606:4700::1111]")).toBe(
    "2606:4700:0:0:0:0:0:1111",
  );
  expect(canonicalAddress("::ffff:1.2.3.4")).toBe("0:0:0:0:0:ffff:102:304");
  expect(canonicalAddress("093.184.216.34")).toBeNull();
  expect(canonicalAddress("llm.example.com")).toBeNull();
});

it("resolves once and returns the checked addresses", async () => {
  const signal = new AbortController().signal;
  let lookups = 0;
  const resolve = () => {
    lookups += 1;
    return Promise.resolve([
      "93.184.216.34",
      "2606:4700::1111",
      "93.184.216.34",
    ]);
  };
  await expect(
    resolvePublicAddresses("llm.example.com", resolve, signal),
  ).resolves.toEqual(["93.184.216.34", "2606:4700:0:0:0:0:0:1111"]);
  expect(lookups).toBe(1);
  await expect(
    resolvePublicAddresses("93.184.216.34", resolve, signal),
  ).resolves.toEqual(["93.184.216.34"]);
  expect(lookups).toBe(1);
});

it("refuses inward host names before any lookup", () => {
  for (const host of [
    "localhost",
    "intranet",
    "gpu.internal",
    "box.local",
    "a.corp",
  ])
    expect(() => {
      assertPublicHostName(host);
    }, host).toThrow();
  expect(() => {
    assertPublicHostName("llm.example.com");
  }).not.toThrow();
});

it("requires every resolved address to be public", async () => {
  const signal = new AbortController().signal;
  await expect(
    assertPublicResolution(
      "rebind.example.com",
      () => Promise.resolve(["93.184.216.34", "10.0.0.5"]),
      signal,
    ),
  ).rejects.toMatchObject({ code: "denied" });
  await expect(
    assertPublicResolution(
      "gone.example.com",
      () => Promise.resolve([]),
      signal,
    ),
  ).rejects.toMatchObject({ code: "unavailable" });
  await expect(
    assertPublicResolution(
      "llm.example.com",
      () => Promise.resolve(["93.184.216.34"]),
      signal,
    ),
  ).resolves.toBeUndefined();
});

it("accepts plain HTTP only to loopback in local development", () => {
  expect(() =>
    modelKeyBaseUrl("openai-compatible", "http://llm.example.com/v1"),
  ).toThrow();
  expect(() =>
    modelKeyBaseUrl("openai-compatible", "https://10.0.0.5/v1"),
  ).toThrow();
  expect(
    modelKeyBaseUrl("openai-compatible", "http://127.0.0.1:11434/v1", {
      allowLocalDev: true,
    }),
  ).toBe("http://127.0.0.1:11434/v1");
});

it("reads a runtime kill switch that can only turn providers off", () => {
  expect(subscriptionKillSwitchFrom("anthropic, openai")).toMatchObject({
    anthropic: true,
    openai: true,
  });
  expect(subscriptionKillSwitchFrom(undefined)).toMatchObject({
    anthropic: false,
  });
  expect(subscriptionKillSwitchFrom("../evil,Anthropic")).not.toHaveProperty(
    "../evil",
  );
});

it("resolves over DNS-over-HTTPS with a redirect mode Workers accept", async () => {
  const inits: RequestInit[] = [];
  const resolve = createDnsOverHttpsResolver((input, init) => {
    inits.push(init ?? {});
    const type = new Request(input).url.endsWith("type=A") ? "A" : "AAAA";
    return Promise.resolve(
      Response.json({
        Answer:
          type === "A"
            ? [
                { type: 5, data: "alias.example." },
                { type: 1, data: "93.184.215.14" },
              ]
            : [],
      }),
    );
  });
  await expect(
    resolve("example.com", new AbortController().signal),
  ).resolves.toEqual(["93.184.215.14"]);
  // Workers throw on `redirect: "error"`; only follow and manual exist.
  expect(inits.map(({ redirect }) => redirect)).toEqual(["manual", "manual"]);
  const redirected = createDnsOverHttpsResolver(() =>
    Promise.resolve(new Response(null, { status: 302 })),
  );
  await expect(
    redirected("example.com", new AbortController().signal),
  ).rejects.toMatchObject({ code: "unavailable" });
});

it("offers Fungi only as a person's Local sign-in and honors its incident switch", () => {
  expect(
    loginAllowed({
      providerId: "fungi",
      method: "subscription",
      host: "local",
      scope: "user",
    }),
  ).toBe(true);
  expect(
    loginAllowed({
      providerId: "fungi",
      method: "subscription",
      host: "local",
      scope: "team",
    }),
  ).toBe(false);
  expect(
    loginAllowed({
      providerId: "fungi",
      method: "subscription",
      host: "hosted",
      scope: "user",
    }),
  ).toBe(false);
  expect(
    loginAllowed({
      providerId: "fungi",
      method: "api_key",
      host: "local",
      scope: "user",
    }),
  ).toBe(false);
  expect(
    loginAllowed(
      {
        providerId: "fungi",
        method: "subscription",
        host: "local",
        scope: "user",
      },
      subscriptionKillSwitchFrom("fungi"),
    ),
  ).toBe(false);
});
