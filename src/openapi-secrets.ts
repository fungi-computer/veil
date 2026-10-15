import { Buffer } from "node:buffer";
import * as Schema from "effect/Schema";
import {
  OpenApiError,
  type OpenApiCredentialKeyring,
  type OpenApiAccess,
} from "./openapi-contract.js";

const keySchema = Schema.String.pipe(
  Schema.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}$/u)),
);
const keyIdSchema = Schema.String.pipe(
  Schema.check(Schema.isPattern(/^[A-Za-z0-9_-]{1,64}$/u)),
);
const envelopeSchema = Schema.Struct({
  version: Schema.Literal(1),
  keyId: keyIdSchema,
  iv: Schema.String.pipe(
    Schema.check(Schema.isPattern(/^[A-Za-z0-9_-]{16}$/u)),
  ),
  ciphertext: Schema.String.pipe(
    Schema.check(Schema.isPattern(/^[A-Za-z0-9_-]{22,22000}$/u)),
  ),
});
const encoder = new TextEncoder();
const binding = (access: OpenApiAccess, keyId: string) =>
  encoder.encode(
    JSON.stringify([
      "fungi.veil.openapi.v1",
      keyId,
      access.teamId,
      access.connectorId,
      access.baseUrl,
      access.auth.kind,
      access.auth.kind === "api_key_header" ||
      access.auth.kind === "api_key_query"
        ? access.auth.param
        : null,
    ]),
  );

/** WebCrypto owns authenticated encryption; the owner address and policy are its AAD. */
export function createOpenApiSecrets(configuration: OpenApiCredentialKeyring) {
  const keys = new Map<
    string,
    Promise<Awaited<ReturnType<typeof crypto.subtle.importKey>>>
  >();
  let activeKeyId: string;
  try {
    activeKeyId = Schema.decodeUnknownSync(keyIdSchema)(
      configuration.activeKeyId,
    );
    for (const [id, encoded] of Object.entries(configuration.keys)) {
      Schema.decodeUnknownSync(keyIdSchema)(id);
      const parsed = Schema.decodeUnknownSync(keySchema)(encoded);
      const bytes = Uint8Array.from(Buffer.from(parsed, "base64url"));
      if (bytes.length !== 32) throw new OpenApiError("unavailable");
      keys.set(
        id,
        crypto.subtle.importKey("raw", bytes, "AES-GCM", false, [
          "encrypt",
          "decrypt",
        ]),
      );
    }
    if (!keys.has(activeKeyId)) throw new OpenApiError("unavailable");
  } catch {
    throw new OpenApiError("unavailable");
  }
  const key = (id: string) => {
    const found = keys.get(id);
    if (!found) throw new OpenApiError("denied");
    return found;
  };
  return {
    async seal(access: OpenApiAccess, credential: string): Promise<string> {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: binding(access, activeKeyId) },
        await key(activeKeyId),
        encoder.encode(credential),
      );
      return JSON.stringify({
        version: 1,
        keyId: activeKeyId,
        iv: Buffer.from(iv).toString("base64url"),
        ciphertext: Buffer.from(ciphertext).toString("base64url"),
      });
    },
    async open(access: OpenApiAccess, sealed: string): Promise<string> {
      try {
        const envelope = Schema.decodeUnknownSync(
          Schema.fromJsonString(envelopeSchema),
        )(sealed);
        const plaintext = await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: Uint8Array.from(Buffer.from(envelope.iv, "base64url")),
            additionalData: binding(access, envelope.keyId),
          },
          await key(envelope.keyId),
          Uint8Array.from(Buffer.from(envelope.ciphertext, "base64url")),
        );
        return new TextDecoder().decode(plaintext);
      } catch {
        throw new OpenApiError("denied");
      }
    },
  };
}
