import {
  createPublicEgressPolicy,
  validatePublicEgressPolicyEntries,
  type PublicEgressPolicy,
} from "@fungi.computer/veil/public-egress-policy";

const configuration: PublicEgressPolicy = {
  deniedCidrs: ["65.21.8.248/32"],
  deniedHostSuffixes: ["fungi.computer"],
};
const valid: boolean = validatePublicEgressPolicyEntries(configuration);
const policy: ReturnType<typeof createPublicEgressPolicy> =
  createPublicEgressPolicy(configuration);
void { valid, policy };
