import * as Schema from "effect/Schema";
import { VeilError } from "./index.js";
import {
  assertPublicResolution,
  createDnsOverHttpsResolver,
  type HostResolver,
} from "./model-key-network.js";
import {
  modelKeyProviders,
  type ModelKeyCustodian,
  type ModelKeyProvider,
} from "./model-keys.js";

/**
 * Model-key egress grants. The Team owner decides which runner may use which
 * sealed key and issues a grant for each decision; the grant travels down in a
 * secret-free projection to the runner's host. Only the custodian can open it:
 * it is AES-GCM sealed under a key derived from the custodian's own credential,
 * bound to the Team and runner, and expires. Opening it is the custodian's
 * authorization check, so no request bytes return to the Team owner.
 */

/** The runner a grant is bound to; the host supplies it from its own admission. */
export type ModelKeyGrantSubject = Readonly<{
  kind: "agent" | "user" | "team-key";
  id: string;
}>;

const grantClaimsSchema = Schema.Struct({
  v: Schema.Literal(1),
  teamId: Schema.NonEmptyString,
  keyId: Schema.NonEmptyString,
  locator: Schema.NonEmptyString,
  provider: Schema.Literals(modelKeyProviders),
  baseUrl: Schema.NonEmptyString,
  /** The personal key's owner, re-checked for membership at each egress. */
  ownerUserId: Schema.NullOr(Schema.NonEmptyString),
  expiresAt: Schema.Number,
});
export type ModelKeyGrantClaims = Readonly<{
  teamId: string;
  keyId: string;
  locator: string;
  provider: ModelKeyProvider;
  baseUrl: string;
  ownerUserId: string | null;
  expiresAt: number;
}>;

const PREFIX = "mkg1";
const encoder = new TextEncoder();

const base64Url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
const fromBase64Url = (text: string): Uint8Array<ArrayBuffer> => {
  const binary = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
};
/** Grants are bound to exactly one Team and runner as authenticated data. */
const binding = (teamId: string, subject: ModelKeyGrantSubject) =>
  encoder.encode(`${PREFIX}\n${teamId}\n${subject.kind}\n${subject.id}`);

/** Issue and open grants under a key only the custodian's credential derives. */
export function createModelKeyGrants(
  options: Readonly<{ custodySecret: string; now?: () => number }>,
) {
  if (options.custodySecret.length === 0) throw new VeilError("unavailable");
  const now = options.now ?? Date.now;
  const key = (async () => {
    const material = await crypto.subtle.importKey(
      "raw",
      encoder.encode(options.custodySecret),
      "HKDF",
      false,
      ["deriveKey"],
    );
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: encoder.encode("fungi.veil.model-key-grant"),
        info: encoder.encode(PREFIX),
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  })();

  return {
    async issue(
      subject: ModelKeyGrantSubject,
      claims: ModelKeyGrantClaims,
    ): Promise<string> {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const sealed = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: binding(claims.teamId, subject),
        },
        await key,
        encoder.encode(JSON.stringify({ v: 1, ...claims })),
      );
      return `${PREFIX}.${base64Url(iv)}.${base64Url(new Uint8Array(sealed))}`;
    },

    /** The custodian's check: authentic, for this Team and runner, unexpired. */
    async open(
      grant: string,
      expected: Readonly<{ teamId: string; subject: ModelKeyGrantSubject }>,
    ): Promise<ModelKeyGrantClaims> {
      const [prefix, iv, sealed, extra] = grant.split(".");
      if (
        prefix !== PREFIX ||
        iv === undefined ||
        sealed === undefined ||
        extra !== undefined
      )
        throw new VeilError("denied");
      let claims: ModelKeyGrantClaims;
      try {
        const opened = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: fromBase64Url(iv),
            additionalData: binding(expected.teamId, expected.subject),
          },
          await key,
          fromBase64Url(sealed),
        );
        claims = Schema.decodeUnknownSync(
          Schema.fromJsonString(grantClaimsSchema),
        )(new TextDecoder().decode(opened));
      } catch {
        throw new VeilError("denied");
      }
      if (claims.teamId !== expected.teamId) throw new VeilError("denied");
      if (claims.expiresAt <= now()) throw new VeilError("expired");
      return claims;
    },
  };
}
export type ModelKeyGrants = ReturnType<typeof createModelKeyGrants>;

/**
 * Final model egress for a runner holding a grant. The custodian opens the
 * grant, re-checks the personal key owner's membership and a Team-named base
 * URL's public resolution, then attaches the sealed key upstream.
 */
export function createModelKeyEgress(
  options: Readonly<{
    grants: ModelKeyGrants;
    custodian: () => ModelKeyCustodian;
    /** Whether the personal key's owner is still a member of the Team. */
    ownerIsMember: (
      teamId: string,
      userId: string,
    ) => Promise<"allowed" | "denied" | "unavailable">;
    resolveHost?: HostResolver;
  }>,
) {
  const resolveHost = options.resolveHost ?? createDnsOverHttpsResolver();
  return {
    async send(
      grant: string,
      expected: Readonly<{
        teamId: string;
        subject: ModelKeyGrantSubject;
        provider: ModelKeyProvider;
      }>,
      request: Request,
    ): Promise<Response> {
      const claims = await options.grants.open(grant, expected);
      if (claims.provider !== expected.provider) throw new VeilError("denied");
      // A departed member's key never pays, even before removal cleanup lands.
      if (claims.ownerUserId !== null) {
        const member = await options.ownerIsMember(
          claims.teamId,
          claims.ownerUserId,
        );
        if (member !== "allowed")
          throw new VeilError(member === "denied" ? "denied" : "unavailable");
      }
      if (claims.provider === "openai-compatible")
        await assertPublicResolution(
          new URL(claims.baseUrl).hostname,
          resolveHost,
          request.signal,
        );
      return await options.custodian().send(
        {
          locator: claims.locator,
          provider: claims.provider,
          baseUrl: claims.baseUrl,
        },
        request,
      );
    },
  };
}
export type ModelKeyEgress = ReturnType<typeof createModelKeyEgress>;
