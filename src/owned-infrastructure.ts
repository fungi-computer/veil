import { validatePublicEgressPolicyEntries } from "./public-egress-policy.js";
import { z } from "zod";

/** Inventory structure only; Veil owns CIDR/domain matching and public-unicast admission. */
const ownedInfrastructureSchema = z
  .strictObject({
    version: z.literal(1),
    publicAddressAdmission: z.literal("@fungi.computer/veil/public-fetch"),
    deniedCidrs: z.array(z.string().min(1).max(128)).min(1).max(256),
    deniedHostSuffixes: z.array(z.string().min(1).max(253)).min(1).max(256),
  })
  .refine(validatePublicEgressPolicyEntries, {
    message:
      "Owned infrastructure entries must be canonical, distinct CIDRs and domain suffixes",
  });

/** CTO-approved host inventory. Never populate it from a Connector or OpenAPI document. */
export type OwnedInfrastructure = z.infer<typeof ownedInfrastructureSchema>;

/** Decode an inventory at the file or binding boundary; missing/empty data refuses. */
export function parseOwnedInfrastructure(input: unknown): OwnedInfrastructure {
  return ownedInfrastructureSchema.parse(input);
}
