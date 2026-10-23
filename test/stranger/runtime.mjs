import assert from "node:assert/strict";
import {
  createPublicEgressPolicy,
  validatePublicEgressPolicyEntries,
} from "@fungi.computer/veil/public-egress-policy";

const configuration = {
  deniedCidrs: ["65.21.8.248/32"],
  deniedHostSuffixes: ["fungi.computer"],
};
assert.equal(validatePublicEgressPolicyEntries(configuration), true);
assert.doesNotThrow(() => createPublicEgressPolicy(configuration));
for (const deniedCidrs of [["0.0.0.0/0"], ["188.245.165.189/24"]]) {
  assert.equal(validatePublicEgressPolicyEntries({ deniedCidrs }), false);
  assert.throws(() => createPublicEgressPolicy({ deniedCidrs }));
}
assert.equal(
  validatePublicEgressPolicyEntries({
    deniedHostSuffixes: ["*.fungi.computer"],
  }),
  false,
);
