import { createHmac } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { createWebhookTriggerSecrets } from "../src/webhook-trigger-secrets.js";

const masterKey = Buffer.alloc(32, 7).toString("base64url");
const custody = createWebhookTriggerSecrets(masterKey);
const address = { teamId: "team-a", bindingId: "bind-a", secretGeneration: 2 };
const body = new TextEncoder().encode('{"event":"ready"}');
const now = 1_800_000_000;

afterEach(() => {
  vi.restoreAllMocks();
});

const request = (headers: Record<string, string>, urlToken: string | null) => ({
  headers: new Headers(headers),
  body,
  urlToken,
  nowSeconds: now,
});

async function fungiHeaders(
  secretAddress = address,
  timestamp = String(now),
): Promise<Record<string, string>> {
  const secret = await custody.reveal(secretAddress);
  const mac = createHmac("sha256", Buffer.from(secret, "base64url"))
    .update(`${timestamp}.`)
    .update(body)
    .digest("hex");
  return { "x-fungi-timestamp": timestamp, "x-fungi-signature": `v1=${mac}` };
}

async function githubHeaders(
  secretAddress = address,
): Promise<Record<string, string>> {
  const secret = await custody.reveal(secretAddress);
  const mac = createHmac("sha256", secret).update(body).digest("hex");
  return {
    "x-hub-signature-256": `sha256=${mac}`,
    "x-github-delivery": "72d3162e-cc78-11e3-81ab-4c9367dc0958",
  };
}

it("derives one unrelated secret per team, binding and generation", async () => {
  const secrets = await Promise.all([
    custody.reveal(address),
    custody.reveal({ ...address, teamId: "team-b" }),
    custody.reveal({ ...address, bindingId: "bind-b" }),
    custody.reveal({ ...address, secretGeneration: 3 }),
  ]);
  expect(new Set(secrets).size).toBe(4);
  expect(await custody.reveal(address)).toBe(secrets[0]);
  expect(secrets[0]).toMatch(/^[A-Za-z0-9_-]{43}$/u);
});

it("verifies a fungi-v1 request addressed to the current generation", async () => {
  const result = await custody.verify({
    verifier: "fungi-v1",
    address,
    ...request(await fungiHeaders(), null),
  });
  expect(result.status).toBe("ok");
});

it("verifies a GitHub request and returns X-GitHub-Delivery as the event id", async () => {
  await expect(
    custody.verify({
      verifier: "github",
      address,
      ...request(await githubHeaders(), null),
    }),
  ).resolves.toEqual({
    status: "ok",
    eventId: "72d3162e-cc78-11e3-81ab-4c9367dc0958",
  });
});

it("verifies the secret-url token the owner was shown", async () => {
  const token = await custody.reveal(address);
  const result = await custody.verify({
    verifier: "secret-url",
    address,
    ...request({}, token),
  });
  expect(result.status).toBe("ok");
});

it("refuses every verifier's traffic made under an old generation", async () => {
  const old = { ...address, secretGeneration: 1 };
  const refusal = { status: "refused", reason: "bad_signature" };
  await expect(
    custody.verify({
      verifier: "fungi-v1",
      address,
      ...request(await fungiHeaders(old), null),
    }),
  ).resolves.toEqual(refusal);
  await expect(
    custody.verify({
      verifier: "github",
      address,
      ...request(await githubHeaders(old), null),
    }),
  ).resolves.toEqual(refusal);
  await expect(
    custody.verify({
      verifier: "secret-url",
      address,
      ...request({}, await custody.reveal(old)),
    }),
  ).resolves.toEqual(refusal);
});

it("refuses traffic signed for another binding or team", async () => {
  for (const other of [
    { ...address, bindingId: "bind-b" },
    { ...address, teamId: "team-b" },
  ]) {
    await expect(
      custody.verify({
        verifier: "fungi-v1",
        address,
        ...request(await fungiHeaders(other), null),
      }),
    ).resolves.toEqual({ status: "refused", reason: "bad_signature" });
  }
});

it("refuses a stale fungi-v1 timestamp even when correctly signed", async () => {
  const stale = String(now - 301);
  await expect(
    custody.verify({
      verifier: "fungi-v1",
      address,
      ...request(await fungiHeaders(address, stale), null),
    }),
  ).resolves.toEqual({ status: "refused", reason: "stale" });
});

it("never puts a secret in a thrown error, a result or a log line", async () => {
  const logs = [
    vi.spyOn(console, "log"),
    vi.spyOn(console, "info"),
    vi.spyOn(console, "warn"),
    vi.spyOn(console, "error"),
    vi.spyOn(console, "debug"),
  ];
  const secret = await custody.reveal(address);
  const wrong = `${secret.slice(0, 42)}${secret.endsWith("A") ? "B" : "A"}`;
  const results: unknown[] = [];
  for (const verifier of ["fungi-v1", "github", "secret-url"] as const)
    results.push(
      await custody.verify({
        verifier,
        address,
        ...request(
          {
            "x-fungi-timestamp": String(now),
            "x-fungi-signature": `v1=${"0".repeat(64)}`,
            "x-hub-signature-256": `sha256=${"0".repeat(64)}`,
            "x-github-delivery": "delivery-1",
          },
          wrong,
        ),
      }),
    );
  const failures: string[] = [];
  const badKey = masterKey.replace(/.$/u, "!");
  try {
    createWebhookTriggerSecrets(badKey);
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    expect(error.message).toBe("Invalid webhook custody key");
    failures.push(String(error));
  }
  await custody
    .reveal({ ...address, bindingId: "" })
    .catch((error: unknown) => failures.push(String(error)));
  const everything = JSON.stringify([results, failures]);
  expect(failures).toHaveLength(2);
  for (const sensitive of [secret, wrong, masterKey, badKey])
    expect(everything).not.toContain(sensitive);
  for (const log of logs) expect(log).not.toHaveBeenCalled();
});
