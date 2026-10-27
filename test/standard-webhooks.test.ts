import { createHmac } from "node:crypto";
import { expect, it } from "vitest";
import {
  EVENT_VERIFIER_SECURITY,
  standardWebhookSecret,
  verifyStandardWebhooks,
  type EventRequest,
} from "../src/event-verifiers.js";

// The reference vector from the Standard Webhooks specification.
const vectorSecret = "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"; //gitleaks:allow
const vectorBody = new TextEncoder().encode('{"test": 2432232314}');
const vector = (
  headers: Record<string, string>,
  nowSeconds = 1614265330,
): EventRequest => ({
  headers: new Headers({
    "webhook-id": "msg_p5jXN8AQM9LWM0D4loKWxJek",
    "webhook-timestamp": "1614265330",
    "webhook-signature": "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
    ...headers,
  }),
  body: vectorBody,
  urlToken: null,
  nowSeconds,
});

it("accepts the specification's reference vector, with the signed id as the event id", () => {
  expect(verifyStandardWebhooks(vectorSecret, vector({}))).toEqual({
    status: "ok",
    eventId: "msg_p5jXN8AQM9LWM0D4loKWxJek",
  });
  expect(EVENT_VERIFIER_SECURITY["standard-webhooks"]).toBe("signed");
});

it("accepts any listed v1 signature, so senders can rotate keys", () => {
  expect(
    verifyStandardWebhooks(
      vectorSecret,
      vector({
        "webhook-signature":
          "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc= v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
      }),
    ).status,
  ).toBe("ok");
});

it("refuses a re-used signature under another id, a wrong secret, a stale timestamp and malformed headers", () => {
  const refused = (reason: string) => ({ status: "refused", reason });
  // The id is signed: changing it to force a new event breaks the signature.
  expect(
    verifyStandardWebhooks(vectorSecret, vector({ "webhook-id": "msg_other" })),
  ).toEqual(refused("bad_signature"));
  expect(
    verifyStandardWebhooks(
      Buffer.alloc(24, 1).toString("base64url"),
      vector({}),
    ),
  ).toEqual(refused("bad_signature"));
  expect(
    verifyStandardWebhooks(vectorSecret, vector({}, 1614265330 + 301)),
  ).toEqual(refused("stale"));
  for (const [header, value] of [
    ["webhook-signature", "v2,abc"],
    ["webhook-signature", "v1,not base64!"],
    ["webhook-timestamp", "soon"],
    ["webhook-id", "x".repeat(257)],
  ] as const)
    expect(
      verifyStandardWebhooks(vectorSecret, vector({ [header]: value })),
    ).toEqual(refused("malformed"));
  expect(
    verifyStandardWebhooks(vectorSecret, {
      ...vector({}),
      headers: new Headers({ "webhook-id": "msg_x" }),
    }),
  ).toEqual(refused("missing"));
});

it("shows a binding's secret in the whsec_ form senders use, over the same key bytes", () => {
  const revealed = Buffer.alloc(32, 9).toString("base64url");
  const shown = standardWebhookSecret(revealed);
  expect(shown).toMatch(/^whsec_[A-Za-z0-9+/]+=*$/u);
  const key = Buffer.from(shown.slice(6), "base64");
  const signature = createHmac("sha256", key)
    .update(`msg_1.1800000000.{}`)
    .digest("base64");
  expect(
    verifyStandardWebhooks(revealed, {
      headers: new Headers({
        "webhook-id": "msg_1",
        "webhook-timestamp": "1800000000",
        "webhook-signature": `v1,${signature}`,
      }),
      body: new TextEncoder().encode("{}"),
      urlToken: null,
      nowSeconds: 1800000000,
    }),
  ).toEqual({ status: "ok", eventId: "msg_1" });
});
