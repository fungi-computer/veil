import { createHmac } from "node:crypto";
import { expect, it } from "vitest";
import {
  EVENT_VERIFIER_SECURITY,
  verifyFungiV1,
  verifyGithub,
  verifySecretUrl,
  type EventRequest,
} from "../src/event-verifiers.js";

// The test vector from GitHub's "Validating webhook deliveries" documentation.
const githubSecret = "It's a Secret to Everybody";
const githubBody = new TextEncoder().encode("Hello, World!");
const githubSignature =
  "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

const base = (
  headers: Record<string, string>,
  overrides: Partial<EventRequest> = {},
): EventRequest => ({
  headers: new Headers(headers),
  body: githubBody,
  urlToken: null,
  nowSeconds: 1_800_000_000,
  ...overrides,
});

it("accepts GitHub's documented test vector", () => {
  expect(
    verifyGithub(
      githubSecret,
      base({
        "x-hub-signature-256": githubSignature,
        "x-github-delivery": "72d3162e-cc78-11e3-81ab-4c9367dc0958",
      }),
    ),
  ).toEqual({ status: "ok", eventId: "72d3162e-cc78-11e3-81ab-4c9367dc0958" });
});

it("refuses GitHub requests with a wrong secret, altered body or bad headers", () => {
  const headers = {
    "x-hub-signature-256": githubSignature,
    "x-github-delivery": "abc-123",
  };
  const refusal = (reason: string) => ({ status: "refused", reason });
  expect(verifyGithub("another secret", base(headers))).toEqual(
    refusal("bad_signature"),
  );
  expect(
    verifyGithub(
      githubSecret,
      base(headers, { body: new TextEncoder().encode("Hello, World?") }),
    ),
  ).toEqual(refusal("bad_signature"));
  expect(
    verifyGithub(githubSecret, base({ "x-github-delivery": "abc-123" })),
  ).toEqual(refusal("missing"));
  expect(
    verifyGithub(
      githubSecret,
      base({ "x-hub-signature-256": githubSignature }),
    ),
  ).toEqual(refusal("missing"));
  // The unprefixed hex digest is not GitHub's header format.
  expect(
    verifyGithub(
      githubSecret,
      base({ ...headers, "x-hub-signature-256": githubSignature.slice(7) }),
    ),
  ).toEqual(refusal("malformed"));
  expect(
    verifyGithub(
      githubSecret,
      base({ ...headers, "x-github-delivery": "not a delivery id" }),
    ),
  ).toEqual(refusal("malformed"));
});

const fungiSecret = Buffer.alloc(32, 9).toString("base64url");
function fungi(
  timestamp: string,
  secret = fungiSecret,
  now = Number(timestamp),
) {
  const mac = createHmac("sha256", Buffer.from(secret, "base64url"))
    .update(`${timestamp}.`)
    .update(githubBody)
    .digest("hex");
  return base(
    { "x-fungi-timestamp": timestamp, "x-fungi-signature": `v1=${mac}` },
    { nowSeconds: now },
  );
}

it("accepts fungi-v1 inside the 300 second skew and refuses outside it", () => {
  const timestamp = 1_800_000_000;
  for (const skew of [0, 300, -300])
    expect(
      verifyFungiV1(
        fungiSecret,
        fungi(String(timestamp), fungiSecret, timestamp + skew),
      ).status,
    ).toBe("ok");
  for (const skew of [301, -301])
    expect(
      verifyFungiV1(
        fungiSecret,
        fungi(String(timestamp), fungiSecret, timestamp + skew),
      ),
    ).toEqual({ status: "refused", reason: "stale" });
});

it("returns the fungi-v1 signature as the event id and refuses wrong secrets", () => {
  const request = fungi("1800000000");
  const ok = verifyFungiV1(fungiSecret, request);
  expect(ok).toEqual({
    status: "ok",
    eventId: request.headers.get("x-fungi-signature")?.slice(3),
  });
  expect(
    verifyFungiV1(Buffer.alloc(32, 1).toString("base64url"), request),
  ).toEqual({ status: "refused", reason: "bad_signature" });
});

it("refuses fungi-v1 requests with missing or malformed headers", () => {
  const refusal = (reason: string) => ({ status: "refused", reason });
  expect(verifyFungiV1(fungiSecret, base({}))).toEqual(refusal("missing"));
  expect(
    verifyFungiV1(fungiSecret, base({ "x-fungi-timestamp": "1800000000" })),
  ).toEqual(refusal("missing"));
  expect(
    verifyFungiV1(
      fungiSecret,
      base({ "x-fungi-timestamp": "yesterday", "x-fungi-signature": "v1=zz" }),
    ),
  ).toEqual(refusal("malformed"));
  expect(
    verifyFungiV1(
      fungiSecret,
      base({
        "x-fungi-timestamp": "1800000000",
        "x-fungi-signature": "0".repeat(64),
      }),
    ),
  ).toEqual(refusal("malformed"));
});

it("checks the secret-url token and labels the verifier less secure", () => {
  const token = Buffer.alloc(32, 5).toString("base64url");
  const wrong = Buffer.alloc(32, 6).toString("base64url");
  const refusal = (reason: string) => ({ status: "refused", reason });
  const ok = verifySecretUrl(token, base({}, { urlToken: token }));
  expect(ok.status).toBe("ok");
  expect(verifySecretUrl(token, base({}, { urlToken: wrong }))).toEqual(
    refusal("bad_signature"),
  );
  expect(verifySecretUrl(token, base({}))).toEqual(refusal("missing"));
  expect(verifySecretUrl(token, base({}, { urlToken: "short" }))).toEqual(
    refusal("malformed"),
  );
  // The sender supplies no id, so two deliveries are two events.
  const again = verifySecretUrl(token, base({}, { urlToken: token }));
  expect(again).not.toEqual(ok);
  expect(EVENT_VERIFIER_SECURITY["secret-url"]).toBe("less_secure");
  expect(EVENT_VERIFIER_SECURITY.github).toBe("signed");
});

it("refuses empty header values as missing", () => {
  expect(
    verifyGithub(
      githubSecret,
      base({ "x-hub-signature-256": "", "x-github-delivery": "abc" }),
    ),
  ).toEqual({ status: "refused", reason: "missing" });
});
