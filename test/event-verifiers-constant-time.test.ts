import nodeCrypto from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import {
  constantTimeEqual,
  verifyFungiV1,
  verifyGithub,
  verifySecretUrl,
} from "../src/event-verifiers.js";

const secret = Buffer.alloc(32, 3).toString("base64url");
const body = new TextEncoder().encode("{}");

const compare = vi.spyOn(nodeCrypto, "timingSafeEqual");

afterEach(() => {
  compare.mockClear();
});

it("compares every verifier's secret-derived bytes with timingSafeEqual", () => {
  const timestamp = "1800000000";
  const fungi = nodeCrypto
    .createHmac("sha256", Buffer.from(secret, "base64url"))
    .update(`${timestamp}.`)
    .update(body)
    .digest("hex");
  const github = nodeCrypto
    .createHmac("sha256", secret)
    .update(body)
    .digest("hex");
  const attempts = [
    verifyFungiV1(secret, {
      headers: new Headers({
        "x-fungi-timestamp": timestamp,
        "x-fungi-signature": `v1=${fungi}`,
      }),
      body,
      urlToken: null,
      nowSeconds: 1_800_000_000,
    }),
    verifyGithub(secret, {
      headers: new Headers({
        "x-hub-signature-256": `sha256=${github}`,
        "x-github-delivery": "d-1",
      }),
      body,
      urlToken: null,
      nowSeconds: 1_800_000_000,
    }),
    verifySecretUrl(secret, {
      headers: new Headers(),
      body,
      urlToken: secret,
      nowSeconds: 1_800_000_000,
    }),
  ];
  expect(attempts.map((attempt) => attempt.status)).toEqual(["ok", "ok", "ok"]);
  expect(compare).toHaveBeenCalledTimes(3);
});

it("still compares when the claimed value is wrong", () => {
  const wrong = Buffer.alloc(32, 4).toString("base64url");
  expect(
    verifySecretUrl(secret, {
      headers: new Headers(),
      body,
      urlToken: wrong,
      nowSeconds: 0,
    }).status,
  ).toBe("refused");
  expect(compare).toHaveBeenCalledTimes(1);
});

it("treats different lengths as unequal without throwing", () => {
  expect(constantTimeEqual(new Uint8Array(3), new Uint8Array(4))).toBe(false);
  expect(constantTimeEqual(new Uint8Array(4), new Uint8Array(4))).toBe(true);
});
