import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { URL } from "node:url";
import { parseOwnedInfrastructure } from "@fungi.computer/veil/owned-infrastructure";
import { createPublicEgressPolicy } from "@fungi.computer/veil/public-egress-policy";

test("built Node ESM parses the approved inventory through its canonical entry validator", () => {
  const inventory = parseOwnedInfrastructure(
    JSON.parse(
      readFileSync(
        new URL(
          "../../../tooling/deployment/owned-infrastructure.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ),
  );
  assert.equal(inventory.version, 1);
  assert.ok(inventory.deniedCidrs.includes("65.21.8.248/32"));
  assert.throws(() =>
    parseOwnedInfrastructure({
      ...inventory,
      deniedCidrs: ["188.245.165.189/24"],
    }),
  );
  assert.throws(() =>
    parseOwnedInfrastructure({
      ...inventory,
      deniedHostSuffixes: ["*.fungi.computer"],
    }),
  );
});

test("built Node ESM policy creation denies owned addresses and suffixes", () => {
  const policy = createPublicEgressPolicy({
    deniedCidrs: ["65.21.8.248/32", "2a01:4f9:3080:405b::/64"],
    deniedHostSuffixes: ["fungi.computer"],
  });
  assert.throws(() => policy.addresses(["65.21.8.248"]), { code: "denied" });
  assert.throws(() => policy.addresses(["2a01:4f9:3080:405b::2"]), {
    code: "denied",
  });
  assert.throws(
    () => policy.destination(new URL("https://docs.fungi.computer")),
    { code: "denied" },
  );
  assert.doesNotThrow(() => policy.addresses(["8.8.8.8"]));
  assert.doesNotThrow(() => policy.destination(new URL("https://example.com")));
});
