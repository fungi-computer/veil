import { describe, expect, it } from "vitest";
import {
  createPublicEgressPolicy,
  validatePublicEgressPolicyEntries,
} from "../src/public-egress-policy.js";

describe("canonical public egress entries", () => {
  it("validates canonical entries used by the host policy", () => {
    expect(
      validatePublicEgressPolicyEntries({
        deniedCidrs: ["65.21.8.248/32", "2a01:4f9:3080:405b::/64"],
        deniedHostSuffixes: ["fungi.computer"],
      }),
    ).toBe(true);
  });
  it.each([
    "*.fungi.computer",
    "com",
    "localhost",
    "1.2.3.4",
    "Fungi.computer",
    ".fungi.computer",
    "fungi.computer.",
  ])(
    "refuses malformed suffix %s in both validation and construction",
    (entry) => {
      const configuration = { deniedHostSuffixes: [entry] };
      expect(validatePublicEgressPolicyEntries(configuration)).toBe(false);
      expect(() => createPublicEgressPolicy(configuration)).toThrow();
    },
  );
  it.each([
    "0.0.0.0/0",
    "::/0",
    "188.245.165.189/24",
    "::ffff:65.21.8.248/128",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "2002::/16",
  ])(
    "refuses malformed CIDR %s in both validation and construction",
    (entry) => {
      const configuration = { deniedCidrs: [entry] };
      expect(validatePublicEgressPolicyEntries(configuration)).toBe(false);
      expect(() => createPublicEgressPolicy(configuration)).toThrow();
    },
  );
});
