import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { VeilError } from "../src/index.js";
import type { ModelKeyCustodian } from "../src/model-keys.js";
import {
  createModelKeyEgress,
  createModelKeyGrants,
  type ModelKeyGrantClaims,
} from "../src/model-key-grants.js";

// V1 acceptance: "guest cannot read any credential value." A guest or
// codemode principal is any caller of `createModelKeyEgress().send` that
// does not hold a Hub-issued, correctly bound grant. Every refusal path below
// must deny the call AND never let the sealed secret surface in the thrown
// error, the returned value, or anything logged while handling the attempt.

const SECRET = "synthetic-guest-refusal-secret-do-not-leak";

let logs: string[] = [];

beforeEach(() => {
  logs = [];
  const capture = (...args: unknown[]) => {
    logs.push(args.map((arg) => String(arg)).join(" "));
  };
  vi.spyOn(console, "log").mockImplementation(capture);
  vi.spyOn(console, "error").mockImplementation(capture);
});
afterEach(() => {
  vi.restoreAllMocks();
});

/** Every observable surface of a failed or successful attempt, flattened to
 * text: the thrown error's own fields, its string form, and anything logged
 * while the attempt was in flight. */
function observedSurfaces(
  error: VeilError | undefined,
  response?: Response,
): string[] {
  const surfaces = [
    String(error),
    error === undefined ? "" : JSON.stringify({ code: error.code }),
    ...logs,
  ];
  if (response) surfaces.push(JSON.stringify([...response.headers.entries()]));
  return surfaces;
}

/** Runs a rejecting `egress.send` attempt and hands back its `VeilError`. */
async function rejectedWith(attempt: Promise<Response>): Promise<VeilError> {
  try {
    await attempt;
  } catch (error) {
    if (error instanceof VeilError) return error;
    throw error;
  }
  throw new Error("expected attempt to reject");
}

function assertNoSecretLeak(surfaces: readonly string[]) {
  for (const surface of surfaces) expect(surface.includes(SECRET)).toBe(false);
}

const owner = { kind: "agent", id: "agent-owner" } as const;
const guest = { kind: "agent", id: "agent-guest" } as const;
const claims: ModelKeyGrantClaims = {
  teamId: "team-real",
  keyId: "mkey-real",
  locator: "mkloc-real",
  provider: "anthropic",
  baseUrl: "https://api.anthropic.com",
  ownerUserId: null,
  expiresAt: Date.now() + 60_000,
};

function makeCustodian(sent: string[]): ModelKeyCustodian {
  return {
    seal: () => Promise.resolve(),
    remove: () => Promise.resolve("deleted"),
    // The real custodian never returns the sealed secret to a caller; this
    // fake keeps that same shape so a regression here would actually fail
    // the leak assertions below rather than passing for the wrong reason.
    send: (access, request) => {
      sent.push(`${access.locator} ${request.url}`);
      return Promise.resolve(
        new Response(JSON.stringify({ ok: true }), { status: 200 }),
      );
    },
  };
}

it("refuses a guest with no grant at all, and leaks nothing while refusing", async () => {
  const grants = createModelKeyGrants({ custodySecret: SECRET });
  const sent: string[] = [];
  const egress = createModelKeyEgress({
    grants,
    custodian: () => makeCustodian(sent),
    ownerIsMember: () => Promise.resolve("allowed"),
  });

  const attempt = egress.send(
    "not-a-real-grant",
    { teamId: "team-real", subject: guest, provider: "anthropic" },
    new Request("https://api.anthropic.com/v1/messages"),
  );
  await expect(attempt).rejects.toMatchObject({ code: "denied" });
  const error = await rejectedWith(attempt);
  assertNoSecretLeak(observedSurfaces(error));
  expect(sent).toHaveLength(0);
});

it("refuses a forged grant string, leaking nothing", async () => {
  const grants = createModelKeyGrants({ custodySecret: SECRET });
  const sent: string[] = [];
  const egress = createModelKeyEgress({
    grants,
    custodian: () => makeCustodian(sent),
    ownerIsMember: () => Promise.resolve("allowed"),
  });
  const real = await grants.issue(owner, claims);
  const [prefix = "", iv = "", sealed = ""] = real.split(".");
  const forged = [
    prefix,
    iv,
    `${sealed.startsWith("A") ? "B" : "A"}${sealed.slice(1)}`,
  ].join(".");

  const attempt = egress.send(
    forged,
    { teamId: "team-real", subject: owner, provider: "anthropic" },
    new Request("https://api.anthropic.com/v1/messages"),
  );
  await expect(attempt).rejects.toMatchObject({ code: "denied" });
  assertNoSecretLeak(observedSurfaces(await rejectedWith(attempt)));
  expect(sent).toHaveLength(0);
});

it("refuses a real grant replayed by a different agent (codemode cannot borrow another Agent's grant)", async () => {
  const grants = createModelKeyGrants({ custodySecret: SECRET });
  const sent: string[] = [];
  const egress = createModelKeyEgress({
    grants,
    custodian: () => makeCustodian(sent),
    ownerIsMember: () => Promise.resolve("allowed"),
  });
  const ownerGrant = await grants.issue(owner, claims);

  const attempt = egress.send(
    ownerGrant,
    { teamId: "team-real", subject: guest, provider: "anthropic" },
    new Request("https://api.anthropic.com/v1/messages"),
  );
  await expect(attempt).rejects.toMatchObject({ code: "denied" });
  assertNoSecretLeak(observedSurfaces(await rejectedWith(attempt)));
  expect(sent).toHaveLength(0);
});

it("refuses a real grant replayed under a different Team, leaking nothing", async () => {
  const grants = createModelKeyGrants({ custodySecret: SECRET });
  const sent: string[] = [];
  const egress = createModelKeyEgress({
    grants,
    custodian: () => makeCustodian(sent),
    ownerIsMember: () => Promise.resolve("allowed"),
  });
  const ownerGrant = await grants.issue(owner, claims);

  const attempt = egress.send(
    ownerGrant,
    { teamId: "team-other", subject: owner, provider: "anthropic" },
    new Request("https://api.anthropic.com/v1/messages"),
  );
  await expect(attempt).rejects.toMatchObject({ code: "denied" });
  assertNoSecretLeak(observedSurfaces(await rejectedWith(attempt)));
  expect(sent).toHaveLength(0);
});

it("refuses an expired grant, leaking nothing", async () => {
  let clock = 1_000;
  const grants = createModelKeyGrants({
    custodySecret: SECRET,
    now: () => clock,
  });
  const sent: string[] = [];
  const egress = createModelKeyEgress({
    grants,
    custodian: () => makeCustodian(sent),
    ownerIsMember: () => Promise.resolve("allowed"),
  });
  const grant = await grants.issue(owner, claims);
  clock = claims.expiresAt + 1;

  const attempt = egress.send(
    grant,
    { teamId: "team-real", subject: owner, provider: "anthropic" },
    new Request("https://api.anthropic.com/v1/messages"),
  );
  await expect(attempt).rejects.toMatchObject({ code: "expired" });
  assertNoSecretLeak(observedSurfaces(await rejectedWith(attempt)));
  expect(sent).toHaveLength(0);
});

it("refuses once the owning member has left the Team, leaking nothing", async () => {
  const grants = createModelKeyGrants({ custodySecret: SECRET });
  const sent: string[] = [];
  const egress = createModelKeyEgress({
    grants,
    custodian: () => makeCustodian(sent),
    ownerIsMember: () => Promise.resolve("denied"),
  });
  const personalGrant = await grants.issue(owner, {
    ...claims,
    ownerUserId: "user-departed",
  });

  const attempt = egress.send(
    personalGrant,
    { teamId: "team-real", subject: owner, provider: "anthropic" },
    new Request("https://api.anthropic.com/v1/messages"),
  );
  await expect(attempt).rejects.toMatchObject({ code: "denied" });
  assertNoSecretLeak(observedSurfaces(await rejectedWith(attempt)));
  expect(sent).toHaveLength(0);
});

it("even a valid, correctly-bound grant never gets the raw credential back: only an injected response", async () => {
  const grants = createModelKeyGrants({ custodySecret: SECRET });
  const sent: string[] = [];
  const egress = createModelKeyEgress({
    grants,
    custodian: () => makeCustodian(sent),
    ownerIsMember: () => Promise.resolve("allowed"),
  });
  const grant = await grants.issue(owner, claims);

  const response = await egress.send(
    grant,
    { teamId: "team-real", subject: owner, provider: "anthropic" },
    new Request("https://api.anthropic.com/v1/messages"),
  );
  expect(response.status).toBe(200);
  const body = await response.text();
  expect(sent).toEqual(["mkloc-real https://api.anthropic.com/v1/messages"]);
  assertNoSecretLeak([body, ...observedSurfaces(undefined, response)]);
});
