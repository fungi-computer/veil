import { z } from "zod";
import {
  verifyFungiV1,
  verifyGithub,
  verifySecretUrl,
  verifyStandardWebhooks,
  type EventRequest,
  type EventVerification,
  type EventVerifier,
} from "./event-verifiers.js";

const secretSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/u);
const addressSchema = z.object({
  teamId: z.string().min(1),
  bindingId: z.string().min(1),
  secretGeneration: z.number().int().nonnegative(),
});

/**
 * One event binding's secret. Rotating bumps `secretGeneration`, which derives
 * a new, unrelated secret; the previous one stops verifying.
 */
export type EventBindingAddress = Readonly<{
  teamId: string;
  bindingId: string;
  secretGeneration: number;
}>;

/** A Worker-secret-backed custodian. Per-binding bytes are derived on demand and never enter TeamDO. */
export function createWebhookTriggerSecrets(masterSecret: string) {
  const decoded = secretSchema.safeParse(masterSecret);
  // Never echo the master secret, even through a parse error.
  if (!decoded.success) throw new Error("Invalid webhook custody key");
  const masterBytes = Uint8Array.from(Buffer.from(decoded.data, "base64url"));
  if (masterBytes.length !== 32) throw new Error("Invalid webhook custody key");
  const master = crypto.subtle.importKey(
    "raw",
    masterBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const reveal = async (input: EventBindingAddress): Promise<string> => {
    const address = addressSchema.safeParse(input);
    if (!address.success) throw new Error("Invalid event binding address");
    const key = await master;
    const bytes = new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(
          JSON.stringify([
            "fungi-event-binding-v1",
            address.data.teamId,
            address.data.bindingId,
            address.data.secretGeneration,
          ]),
        ),
      ),
    );
    return Buffer.from(bytes).toString("base64url");
  };
  return {
    /** Show this only on create or rotate. It is never part of a projection. */
    reveal,
    /**
     * Verify one inbound request against the binding's current generation. A
     * signature or token made under any earlier generation is `bad_signature`.
     */
    async verify(
      input: EventRequest &
        Readonly<{ verifier: EventVerifier; address: EventBindingAddress }>,
    ): Promise<EventVerification> {
      const current = await reveal(input.address);
      switch (input.verifier) {
        case "fungi-v1":
          return verifyFungiV1(current, input);
        case "github":
          return verifyGithub(current, input);
        case "secret-url":
          return verifySecretUrl(current, input);
        case "standard-webhooks":
          return verifyStandardWebhooks(current, input);
      }
    },
  };
}
