import { expect, it } from "vitest";
import type { ModelKeyCustodian } from "../src/model-keys.js";
import {
  createModelKeyEgress,
  createModelKeyGrants,
  type ModelKeyGrantClaims,
} from "../src/model-key-grants.js";

let clock = 1_000;
const grants = createModelKeyGrants({
  custodySecret: "synthetic-custody-secret",
  now: () => clock,
});
const agent = { kind: "agent", id: "agent-a" } as const;
const claims: ModelKeyGrantClaims = {
  teamId: "team-1",
  keyId: "mkey-1",
  locator: "mkloc-private",
  provider: "anthropic",
  baseUrl: "https://api.anthropic.com",
  ownerUserId: null,
  expiresAt: 5_000,
};

it("seals the locator: the grant never shows it and opens only for its Team and runner", async () => {
  clock = 1_000;
  const grant = await grants.issue(agent, claims);
  expect(grant).not.toContain("mkloc");
  expect(grant).toMatch(/^mkg1\.[\w-]+\.[\w-]+$/u);
  await expect(
    grants.open(grant, { teamId: "team-1", subject: agent }),
  ).resolves.toMatchObject({ locator: "mkloc-private", keyId: "mkey-1" });
  for (const expected of [
    { teamId: "team-2", subject: agent },
    { teamId: "team-1", subject: { kind: "agent", id: "agent-b" } as const },
    { teamId: "team-1", subject: { kind: "user", id: "agent-a" } as const },
  ])
    await expect(grants.open(grant, expected)).rejects.toMatchObject({
      code: "denied",
    });
  // A grant from another custodian's credential, or a tampered one, is refused.
  const foreign = await createModelKeyGrants({
    custodySecret: "another-secret",
  }).issue(agent, claims);
  await expect(
    grants.open(foreign, { teamId: "team-1", subject: agent }),
  ).rejects.toMatchObject({ code: "denied" });
  const [prefix = "", iv = "", sealed = ""] = grant.split(".");
  const flipped = [
    prefix,
    iv,
    `${sealed.startsWith("A") ? "B" : "A"}${sealed.slice(1)}`,
  ].join(".");
  await expect(
    grants.open(flipped, { teamId: "team-1", subject: agent }),
  ).rejects.toMatchObject({ code: "denied" });
  clock = 5_000;
  await expect(
    grants.open(grant, { teamId: "team-1", subject: agent }),
  ).rejects.toMatchObject({ code: "expired" });
});

it("egress opens the grant, re-checks owner membership and base resolution, then sends", async () => {
  clock = 1_000;
  const sent: string[] = [];
  const custodian: ModelKeyCustodian = {
    seal: () => Promise.resolve(),
    remove: () => Promise.resolve("deleted"),
    send: (access, request) => {
      sent.push(`${access.locator} ${request.url}`);
      return Promise.resolve(new Response(null, { status: 200 }));
    },
  };
  let member: "allowed" | "denied" = "allowed";
  const egress = createModelKeyEgress({
    grants,
    custodian: () => custodian,
    ownerIsMember: () => Promise.resolve(member),
    resolveHost: (hostname) =>
      Promise.resolve(
        hostname === "rebind.example.com" ? ["10.0.0.5"] : ["93.184.216.34"],
      ),
  });
  const personal = await grants.issue(agent, {
    ...claims,
    ownerUserId: "user-a",
  });
  const expected = {
    teamId: "team-1",
    subject: agent,
    provider: "anthropic",
  } as const;
  const call = () =>
    new Request("https://api.anthropic.com/v1/messages", { method: "POST" });
  expect((await egress.send(personal, expected, call())).status).toBe(200);
  expect(sent).toEqual(["mkloc-private https://api.anthropic.com/v1/messages"]);
  await expect(
    egress.send(personal, { ...expected, provider: "openai" }, call()),
  ).rejects.toMatchObject({ code: "denied" });
  member = "denied";
  await expect(egress.send(personal, expected, call())).rejects.toMatchObject({
    code: "denied",
  });
  const rebound = await grants.issue(agent, {
    ...claims,
    provider: "openai-compatible",
    baseUrl: "https://rebind.example.com/v1",
  });
  await expect(
    egress.send(
      rebound,
      { ...expected, provider: "openai-compatible" },
      new Request("https://rebind.example.com/v1/chat/completions"),
    ),
  ).rejects.toMatchObject({ code: "denied" });
  expect(sent).toHaveLength(1);
});

it("surfaces DNS outages as transient instead of converting them to denial", async () => {
  const grant = await grants.issue(agent, {
    ...claims,
    provider: "openai-compatible",
    baseUrl: "https://llm.example.com/v1",
  });
  const egress = createModelKeyEgress({
    grants,
    custodian: () => {
      throw new Error("custodian must not send after DNS outage");
    },
    ownerIsMember: () => Promise.resolve("allowed"),
    resolveHost: () => Promise.reject(new Error("resolver unavailable")),
  });

  await expect(
    egress.send(
      grant,
      {
        teamId: "team-1",
        subject: agent,
        provider: "openai-compatible",
      },
      new Request("https://llm.example.com/v1/chat/completions"),
    ),
  ).rejects.toMatchObject({ code: "unavailable" });
});
